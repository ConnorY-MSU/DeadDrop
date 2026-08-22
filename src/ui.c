#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "ui.h"

/* See ui.h's top comment for the full design reasoning (concurrency
 * decision, window layout, scope, touch-vs-keyboard). This file has two
 * completely separate implementations selected at compile time:
 *   - __linux__: real ncurses, used on the actual Pi hardware.
 *   - everything else (this project's Windows dev machine): a plain-
 *     stdio fallback that replicates exactly what client.c/server.c/
 *     session.c did before this module existed, so dev-machine
 *     testing/behavior is unchanged - matching hw_expansion.h/hw_oled.h's
 *     established "real implementation on Linux only" precedent.
 */

#ifdef __linux__

#include <ncurses.h>
#include <pthread.h>
#include <unistd.h> /* usleep() - see ui_poll_line()'s comment */

/* --- Module state -------------------------------------------------------
 *
 * ncurses itself is NOT thread-safe: its window/cursor state is global,
 * and session.c's receiver thread (calling ui_add_history()) runs
 * concurrently with the main/sender thread (calling ui_poll_line()/
 * ui_set_status()). ui_mutex serializes every actual ncurses API call.
 *
 * REAL BUG FOUND AND FIXED via live two-Pi hardware testing, worth
 * recording here since the fix shapes ui_poll_line()'s structure below:
 * an earlier version held ui_mutex across wgetch()'s ENTIRE timeout wait
 * (up to STDIN_POLL_MS, called back-to-back in a tight loop from
 * session.c with essentially zero gap between one call's unlock and the
 * next call's lock). That starved the receiver thread's
 * ui_add_history() calls - not a deadlock (it did eventually resolve),
 * but Linux's default pthread mutex provides no fairness/FIFO
 * guarantee, and a thread that immediately tries to re-lock right after
 * unlocking has a real, observed tendency to keep winning the race
 * against a separate waiting thread, sometimes for many seconds.
 * Confirmed via /proc/<tid>/stack: the receiver thread sat in
 * futex_do_wait (waiting on this exact mutex) while the main thread
 * cycled through short, legitimate poll() waits (wgetch()'s own
 * implementation) with almost no time the lock was actually free. Fix:
 * ui_poll_line() now holds the lock only for SHORT slices and
 * explicitly sleeps OUTSIDE the lock between them - see its comment.
 */
static WINDOW *status_win = NULL;
static WINDOW *history_win = NULL;
static WINDOW *input_win = NULL;
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ui_active = 0;

/* Deliberately smaller than SL_MAX_BODY_LEN (message.h's 64 KiB
 * protocol cap) - this bounds one INTERACTIVELY TYPED line through a
 * physical keyboard, character by character, which is a fundamentally
 * different (and much smaller) realistic limit than the protocol's own
 * wire-format cap. Not pulling in message.h here at all keeps ui.c
 * decoupled from the protocol layer, matching "the UI should require
 * zero logic changes to the crypto/protocol layer" from
 * ncurses UI Concepts.md, applied in the other direction too. */
#define UI_INPUT_MAX 2048
static char input_buf[UI_INPUT_MAX];
static size_t input_len = 0;

static void redraw_input_locked(void)
{
    werase(input_win);
    mvwprintw(input_win, 0, 0, "> %s", input_buf);
    wrefresh(input_win);
}

void ui_init(const char *peer_label)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    /* Safety-net cleanup path in addition to the caller's own explicit
     * ui_shutdown() call (client.c/server.c's main()) - a program that
     * exits via an unexpected return/exit() elsewhere without this would
     * leave the terminal in raw/noecho mode, visibly broken for whoever
     * is at the keyboard afterward. ui_shutdown() itself is idempotent
     * (guarded by ui_active), so having both the explicit call AND this
     * atexit() registration is safe, not a double-free-style hazard. */
    atexit(ui_shutdown);

    status_win = newwin(1, COLS, 0, 0);
    history_win = newwin(LINES - 3, COLS, 1, 0);
    input_win = newwin(1, COLS, LINES - 1, 0);

    scrollok(history_win, TRUE);
    keypad(input_win, TRUE);

    input_len = 0;
    input_buf[0] = '\0';

    ui_active = 1;

    ui_set_statusf("Connecting to %s...", peer_label ? peer_label : "?");
    wrefresh(history_win);
    pthread_mutex_lock(&ui_mutex);
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);
}

void ui_set_status(const char *status_text)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    werase(status_win);
    mvwprintw(status_win, 0, 0, "%s", status_text != NULL ? status_text : "");
    wrefresh(status_win);
    /* Put the cursor back in the input line - otherwise it visibly jumps
     * to wherever the status bar last wrote, which looks broken since
     * that's not where the user is actually about to type. */
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);
}

void ui_set_statusf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    if (!ui_active) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ui_set_status(buf);
}

void ui_add_history(const char *prefix, const char *text)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    if (prefix != NULL) {
        wprintw(history_win, "%s: %s\n", prefix, text != NULL ? text : "");
    } else {
        wprintw(history_win, "%s\n", text != NULL ? text : "");
    }
    wrefresh(history_win);
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);
}

void ui_add_historyf(const char *prefix, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!ui_active) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ui_add_history(prefix, buf);
}

/* Each individual lock hold inside ui_poll_line() is capped at this
 * many ms, regardless of the caller's requested total timeout_ms - see
 * ui_mutex's comment above for why. Short enough that the receiver
 * thread gets a real, frequently-repeated (every ~UI_POLL_SLICE_MS)
 * uncontended window to run; long enough that this doesn't turn into a
 * busy-loop. */
#define UI_POLL_SLICE_MS 20

ui_poll_result ui_poll_line(char *out_line, size_t out_line_size,
                             int timeout_ms)
{
    int elapsed_ms = 0;

    if (!ui_active) {
        return UI_POLL_TIMEOUT;
    }

    while (elapsed_ms < timeout_ms) {
        int ch;
        int slice_ms = UI_POLL_SLICE_MS;
        if (elapsed_ms + slice_ms > timeout_ms) {
            slice_ms = timeout_ms - elapsed_ms;
        }

        pthread_mutex_lock(&ui_mutex);
        wtimeout(input_win, slice_ms);
        ch = wgetch(input_win);

        if (ch == ERR) {
            /* Nothing typed during this slice. Unlock and sleep
             * OUTSIDE the lock (not just "unlock then immediately try
             * to relock") - this is the actual fix, not the shorter
             * slice alone: it guarantees a real window, every slice,
             * where this thread isn't even attempting to hold
             * ui_mutex, so a waiting receiver thread has an
             * uncontended chance to acquire it rather than losing the
             * race to this thread's own next lock attempt. */
            pthread_mutex_unlock(&ui_mutex);
            elapsed_ms += slice_ms;
            usleep(1000);
            continue;
        }

        {
            ui_poll_result result = UI_POLL_TIMEOUT;

            if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                if (out_line != NULL && out_line_size > 0) {
                    size_t n = input_len;
                    if (n >= out_line_size) {
                        n = out_line_size - 1;
                    }
                    memcpy(out_line, input_buf, n);
                    out_line[n] = '\0';
                }
                input_len = 0;
                input_buf[0] = '\0';
                redraw_input_locked();
                result = UI_POLL_LINE;
            } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                if (input_len > 0) {
                    input_len--;
                    input_buf[input_len] = '\0';
                    redraw_input_locked();
                }
            } else if (ch >= 32 && ch < 127) {
                if (input_len + 1 < sizeof(input_buf)) {
                    input_buf[input_len++] = (char)ch;
                    input_buf[input_len] = '\0';
                    redraw_input_locked();
                }
                /* else: silently drop the keystroke once UI_INPUT_MAX
                 * is hit - an honest, deliberate cap (see its #define),
                 * not a bug. */
            }
            /* Any other key (arrows, function keys, resize, etc.):
             * ignored - out of scope for this project's UI, see ui.h's
             * touch/keyboard scope note for the same kind of
             * deliberate, documented limit. */

            pthread_mutex_unlock(&ui_mutex);

            if (result == UI_POLL_LINE) {
                return result;
            }
            /* A real keystroke that wasn't a submitted line yet (a
             * regular character, a backspace) - keep polling for the
             * rest of the caller's requested timeout, matching the
             * original "wait up to timeout_ms total" contract. */
            elapsed_ms += slice_ms;
        }
    }

    return UI_POLL_TIMEOUT;
}

void ui_shutdown(void)
{
    if (ui_active) {
        ui_active = 0;
        endwin();
    }
}

#else /* !__linux__ */

/* --- Non-Linux fallback: plain stdio, replicating exactly what
 * session.c's own printf/fgets-based console handling did before this
 * module existed. See stdin_ready()'s comment below for the platform
 * split it was moved here from (session.c no longer needs to know any
 * of this). --- */

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/select.h>
#endif

static char fallback_peer_label[32];
static int fallback_prompt_shown = 0;

/*
 * stdin_ready - platform-specific bounded poll, moved verbatim from
 * session.c (see git history / TESTING.md for the original design
 * note) now that ui.c owns all console I/O instead. POSIX: select() on
 * fd 0. Windows: Winsock's select() only accepts socket handles, not
 * the console's stdin handle, so this uses WaitForSingleObject()
 * instead - see the original note for the accepted dev-machine-only
 * imprecision this carries (a signaled console handle doesn't
 * guarantee a full line is ready).
 */
#ifdef _WIN32
static int stdin_ready(int timeout_ms)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD rc;

    if (h == INVALID_HANDLE_VALUE || h == NULL) {
        return 1;
    }
    rc = WaitForSingleObject(h, (DWORD)timeout_ms);
    return rc == WAIT_OBJECT_0;
}
#else
static int stdin_ready(int timeout_ms)
{
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(0, &fds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    return select(1, &fds, NULL, NULL, &tv) > 0;
}
#endif

void ui_init(const char *peer_label)
{
    snprintf(fallback_peer_label, sizeof(fallback_peer_label), "%s",
             peer_label != NULL ? peer_label : "?");
    fallback_prompt_shown = 0;
}

void ui_set_status(const char *status_text)
{
    printf("%s\n", status_text != NULL ? status_text : "");
    fflush(stdout);
}

void ui_set_statusf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

void ui_add_history(const char *prefix, const char *text)
{
    if (prefix != NULL) {
        printf("\n%s: %s\n", prefix, text != NULL ? text : "");
    } else {
        printf("\n%s\n", text != NULL ? text : "");
    }
    fallback_prompt_shown = 0; /* redraw "> " on the next poll */
    fflush(stdout);
}

void ui_add_historyf(const char *prefix, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ui_add_history(prefix, buf);
}

ui_poll_result ui_poll_line(char *out_line, size_t out_line_size,
                             int timeout_ms)
{
    if (!fallback_prompt_shown) {
        printf("> ");
        fflush(stdout);
        fallback_prompt_shown = 1;
    }

    if (!stdin_ready(timeout_ms)) {
        return UI_POLL_TIMEOUT;
    }

    if (out_line == NULL || out_line_size == 0) {
        return UI_POLL_TIMEOUT;
    }

    if (fgets(out_line, (int)out_line_size, stdin) == NULL) {
        return UI_POLL_QUIT;
    }

    {
        size_t len = strlen(out_line);
        while (len > 0 && (out_line[len - 1] == '\n' ||
                            out_line[len - 1] == '\r')) {
            out_line[--len] = '\0';
        }
    }

    fallback_prompt_shown = 0;
    return UI_POLL_LINE;
}

void ui_shutdown(void)
{
    /* no-op - stdio needs no cleanup */
}

#endif /* __linux__ */

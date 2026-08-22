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
#include <time.h>

#include "lock.h"

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

/* --- Lock screen (Week 4 Days 2-3 Part E) -------------------------------
 *
 * Real design decisions, per ncurses UI Concepts.md - see lock.h for the
 * PIN storage side of this:
 * - HIDDEN VS VISIBLE: message history and the compose line are hidden
 *   while locked; the status bar (connection state) stays visible and
 *   fully independent of lock state - the device should still visibly
 *   prove it's doing its job from across the room. See ui_add_history()
 *   below for exactly how "hidden but still received" is implemented.
 * - ENTRY POINT: Ctrl+L, a single discoverable keybinding doing double
 *   duty - "lock now" if a PIN exists and the UI is unlocked, "start
 *   setting a PIN" if none exists yet. A device with no PIN configured
 *   starts unlocked (nothing to protect) with an in-history hint on how
 *   to set one, rather than being permanently un-lockable or demanding
 *   PIN setup before the device is otherwise usable.
 * - LOCK TIMING: locked by default on boot whenever a PIN has ever been
 *   set (checked once in ui_init() via lock_pin_exists()). Inactivity
 *   auto-lock after UI_INACTIVITY_TIMEOUT_SECONDS of no keystrokes -
 *   chosen as a middle ground: long enough that someone actively reading
 *   or replying to messages isn't constantly re-locked, short enough
 *   that walking away doesn't leave message content exposed for long.
 * - RATE LIMITING: yes, a short, increasing delay after each wrong PIN
 *   (capped at 5s) - decided even though the actual threat model here
 *   (ncurses UI Concepts.md: reaching this screen at all already
 *   requires physical possession of a powered, connected device) doesn't
 *   strictly demand it, because it costs almost nothing to implement and
 *   adds a real speed bump against a scripted/macro brute-force attempt
 *   via a physically attached keyboard.
 * - DECOUPLING: this state machine touches ONLY ncurses windows and the
 *   pure lock.c PIN-hash module - it never receives a socket, a
 *   WOLFSSL*, or a sl_session_state*, so there is no code path by which
 *   it COULD disrupt the network/crypto layer, rate-limiting included.
 *   Proven, not just asserted, via a real cross-device test - see
 *   TESTING.md.
 */
typedef enum {
    UI_MODE_NORMAL,
    UI_MODE_LOCKED,
    UI_MODE_SET_PIN_NEW,
    UI_MODE_SET_PIN_CONFIRM
} ui_mode_t;

static ui_mode_t ui_mode = UI_MODE_NORMAL;
static int pin_configured = 0; /* cached lock_pin_exists(), see ui_init() */

static char pin_entry_buf[LOCK_PIN_MAX_LEN + 1];
static size_t pin_entry_len = 0;
static char pin_first_entry_buf[LOCK_PIN_MAX_LEN + 1]; /* holds the first
    of two entries during UI_MODE_SET_PIN_NEW -> _CONFIRM */
static size_t pin_first_entry_len = 0;

static int wrong_attempt_count = 0;
static time_t next_allowed_check_time = 0;

#define UI_INACTIVITY_TIMEOUT_SECONDS 120
static time_t last_activity_time = 0;

/* Must be called with ui_mutex held. Replaces history_win's PHYSICAL
 * content with a locked banner, then STOPS refreshing history_win (see
 * ui_add_history() below) until unlock - real incoming messages keep
 * being written into history_win's off-screen buffer the whole time via
 * wprintw() there, regardless of lock state (the receiver thread calling
 * ui_add_history() never changes behavior based on lock state - see this
 * block's DECOUPLING note above), they just don't reach the physical
 * screen until wrefresh(history_win) happens again at unlock. */
static void draw_locked_overlay_locked(void)
{
    werase(history_win);
    mvwprintw(history_win, 0, 0,
              "Locked. Messages are still being received normally in the "
              "background.\nEnter your PIN below and press Enter to "
              "unlock.");
    wrefresh(history_win);
}

/* Mode-aware input-line redraw - replaces the old single-purpose
 * "redraw the compose line" function. Must be called with ui_mutex held. */
static void redraw_input_locked(void)
{
    size_t i;

    switch (ui_mode) {
    case UI_MODE_LOCKED:
        werase(input_win);
        mvwprintw(input_win, 0, 0, "Enter PIN to unlock: ");
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        wrefresh(input_win);
        break;
    case UI_MODE_SET_PIN_NEW:
        werase(input_win);
        mvwprintw(input_win, 0, 0, "Set a PIN (min %d chars): ",
                  LOCK_PIN_MIN_LEN);
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        wrefresh(input_win);
        break;
    case UI_MODE_SET_PIN_CONFIRM:
        werase(input_win);
        mvwprintw(input_win, 0, 0, "Confirm PIN: ");
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        wrefresh(input_win);
        break;
    case UI_MODE_NORMAL:
    default:
        werase(input_win);
        mvwprintw(input_win, 0, 0, "> %s", input_buf);
        wrefresh(input_win);
        break;
    }
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
    pin_entry_len = 0;
    pin_entry_buf[0] = '\0';
    pin_first_entry_len = 0;
    wrong_attempt_count = 0;
    next_allowed_check_time = 0;
    last_activity_time = time(NULL);

    /* Locked by default on boot whenever a PIN has ever been set on this
     * device (non-negotiable per the build log); a device with no PIN
     * configured yet starts unlocked - see this block's top comment. */
    pin_configured = lock_pin_exists();
    ui_mode = pin_configured ? UI_MODE_LOCKED : UI_MODE_NORMAL;

    ui_active = 1;

    pthread_mutex_lock(&ui_mutex);
    if (ui_mode == UI_MODE_LOCKED) {
        draw_locked_overlay_locked();
    } else {
        wrefresh(history_win);
    }
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);

    ui_set_statusf("Connecting to %s...", peer_label ? peer_label : "?");

    if (!pin_configured) {
        ui_add_history(NULL, "No PIN set - press Ctrl+L to set one and "
                              "enable the lock screen.");
    }
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
    /* Always write into history_win's buffer (above), regardless of lock
     * state - see this file's lock-screen block comment's DECOUPLING
     * note: the receiver thread calling this must never behave
     * differently based on UI lock state. Only the PHYSICAL screen
     * update is gated: while locked, skip wrefresh() so the
     * accumulating real content stays invisible behind the lock overlay
     * (drawn once, at lock time) until unlock explicitly reveals it. */
    if (ui_mode != UI_MODE_LOCKED) {
        wrefresh(history_win);
    }
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
        const char *pending_history_msg = NULL; /* see below - can't call
            ui_add_history() while ui_mutex is already held (non-recursive
            mutex), so a permanent-history confirmation gets queued here
            and added AFTER unlocking this slice's critical section */
        int slice_ms = UI_POLL_SLICE_MS;
        if (elapsed_ms + slice_ms > timeout_ms) {
            slice_ms = timeout_ms - elapsed_ms;
        }

        pthread_mutex_lock(&ui_mutex);

        /* Inactivity auto-lock - see this file's lock-screen block
         * comment for the chosen timeout and reasoning. Only relevant
         * when currently unlocked AND a PIN actually exists to lock
         * with (locking a device with nothing configured to unlock
         * again would just be a permanent, pointless lockout). */
        if (ui_mode == UI_MODE_NORMAL && pin_configured &&
            difftime(time(NULL), last_activity_time) >=
                UI_INACTIVITY_TIMEOUT_SECONDS) {
            ui_mode = UI_MODE_LOCKED;
            pin_entry_len = 0;
            pin_entry_buf[0] = '\0';
            draw_locked_overlay_locked();
            redraw_input_locked();
        }

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

            if (ch == 12 && ui_mode != UI_MODE_LOCKED) {
                /* Ctrl+L (ASCII 12) - the lock screen's single
                 * discoverable entry point, doing double duty per this
                 * file's lock-screen block comment. Ignored while
                 * already LOCKED (nothing meaningful for it to do) or
                 * mid-PIN-setup (avoid an inconsistent half-entered
                 * state). */
                if (pin_configured) {
                    ui_mode = UI_MODE_LOCKED;
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                    draw_locked_overlay_locked();
                } else if (ui_mode == UI_MODE_NORMAL) {
                    ui_mode = UI_MODE_SET_PIN_NEW;
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                }
                redraw_input_locked();
            } else if (ui_mode == UI_MODE_NORMAL) {
                last_activity_time = time(NULL);
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
                    /* else: silently drop the keystroke once
                     * UI_INPUT_MAX is hit - an honest, deliberate cap
                     * (see its #define), not a bug. */
                }
                /* Any other key (arrows, function keys, resize, etc.):
                 * ignored - out of scope for this project's UI, see
                 * ui.h's touch/keyboard scope note for the same kind
                 * of deliberate, documented limit. */
            } else if (ui_mode == UI_MODE_LOCKED) {
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    time_t now = time(NULL);
                    if (now < next_allowed_check_time) {
                        char msg[64];
                        snprintf(msg, sizeof(msg),
                                 "Please wait %ld more second(s).",
                                 (long)(next_allowed_check_time - now));
                        werase(input_win);
                        mvwprintw(input_win, 0, 0, "%s", msg);
                        wrefresh(input_win);
                    } else if (lock_check_pin(pin_entry_buf, pin_entry_len)) {
                        ui_mode = UI_MODE_NORMAL;
                        wrong_attempt_count = 0;
                        next_allowed_check_time = 0;
                        last_activity_time = time(NULL);
                        /* Reveal history_win: it was never wrefresh()'d
                         * while locked (see ui_add_history()), so
                         * touchwin() is needed to force a full redraw -
                         * ncurses' normal diff-based refresh could
                         * otherwise miss content that changed while
                         * this window wasn't the one being refreshed. */
                        touchwin(history_win);
                        wrefresh(history_win);
                        redraw_input_locked();
                    } else {
                        int delay;

                        wrong_attempt_count++;
                        delay = wrong_attempt_count;
                        if (delay > 5) {
                            delay = 5;
                        }
                        next_allowed_check_time = time(NULL) + delay;

                        {
                            char msg[64];
                            snprintf(msg, sizeof(msg),
                                     "Wrong PIN (wait %ds before next "
                                     "try).", delay);
                            werase(input_win);
                            mvwprintw(input_win, 0, 0, "%s", msg);
                            wrefresh(input_win);
                        }
                    }
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (pin_entry_len > 0) {
                        pin_entry_len--;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                } else if (ch >= 32 && ch < 127) {
                    if (pin_entry_len + 1 < sizeof(pin_entry_buf)) {
                        pin_entry_buf[pin_entry_len++] = (char)ch;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                }
            } else if (ui_mode == UI_MODE_SET_PIN_NEW) {
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    if (pin_entry_len < LOCK_PIN_MIN_LEN) {
                        char msg[64];
                        snprintf(msg, sizeof(msg),
                                 "Too short - min %d chars. Try again:",
                                 LOCK_PIN_MIN_LEN);
                        werase(input_win);
                        mvwprintw(input_win, 0, 0, "%s", msg);
                        wrefresh(input_win);
                        pin_entry_len = 0;
                        pin_entry_buf[0] = '\0';
                    } else {
                        memcpy(pin_first_entry_buf, pin_entry_buf,
                               pin_entry_len);
                        pin_first_entry_len = pin_entry_len;
                        pin_entry_len = 0;
                        pin_entry_buf[0] = '\0';
                        ui_mode = UI_MODE_SET_PIN_CONFIRM;
                        redraw_input_locked();
                    }
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (pin_entry_len > 0) {
                        pin_entry_len--;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                } else if (ch >= 32 && ch < 127) {
                    if (pin_entry_len + 1 < sizeof(pin_entry_buf)) {
                        pin_entry_buf[pin_entry_len++] = (char)ch;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                }
            } else if (ui_mode == UI_MODE_SET_PIN_CONFIRM) {
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    if (pin_entry_len == pin_first_entry_len &&
                        memcmp(pin_entry_buf, pin_first_entry_buf,
                               pin_entry_len) == 0) {
                        lock_set_pin(pin_first_entry_buf,
                                     pin_first_entry_len);
                        pin_configured = 1;
                        pending_history_msg =
                            "PIN set. Ctrl+L to lock now, or it will "
                            "lock automatically after inactivity.";
                    } else {
                        pending_history_msg =
                            "PINs didn't match - PIN not changed. "
                            "Press Ctrl+L to try again.";
                    }
                    ui_mode = UI_MODE_NORMAL;
                    last_activity_time = time(NULL);
                    memset(pin_first_entry_buf, 0,
                           sizeof(pin_first_entry_buf));
                    pin_first_entry_len = 0;
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                    redraw_input_locked();
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (pin_entry_len > 0) {
                        pin_entry_len--;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                } else if (ch >= 32 && ch < 127) {
                    if (pin_entry_len + 1 < sizeof(pin_entry_buf)) {
                        pin_entry_buf[pin_entry_len++] = (char)ch;
                        pin_entry_buf[pin_entry_len] = '\0';
                        redraw_input_locked();
                    }
                }
            }

            pthread_mutex_unlock(&ui_mutex);

            if (pending_history_msg != NULL) {
                ui_add_history(NULL, pending_history_msg);
            }

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

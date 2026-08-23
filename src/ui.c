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
#include "wifi.h"
#include "touch.h"
#include "hw_expansion.h"
#include "hw_oled.h"
#include "msglog.h"
#include "outbox.h"

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
static WINDOW *history_border_win = NULL; /* outer window, box() only */
static WINDOW *history_win = NULL;        /* derwin() inside the above -
    all existing call sites keep using this name/window for actual
    content; only ui_init() and the touch row-math needed to change to
    account for the border. See this file's STYLING block comment. */
static WINDOW *input_border_win = NULL;   /* outer window, box() only */
static WINDOW *input_win = NULL;          /* derwin() inside the above */
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ui_active = 0;

/* --- Styling (Week 4 Days 2-3). Structural aesthetic pass on top of
 * Phase 1's foundation (color, bordered panels, message-source
 * color-coding): a boot splash, a persistent status-bar brand prefix, a
 * restyled lock screen, and a two-tone compose prompt - all kept as-is
 * across a color revision. The FIRST color pass here was a deliberately
 * saturated "cyberpunk neon" look (magenta/cyan/yellow, heavy A_BOLD),
 * confirmed working on real hardware; the user then asked for something
 * SOFTER, closer to a standard terminal application - this palette is
 * that second pass. Deliberately dropped A_BOLD almost everywhere
 * (bold is what pushed the ANSI 8-color palette into its saturated
 * "bright" variants - removing it is most of what "softer" actually
 * means here, more than the specific hues chosen) and moved from
 * magenta to a conventional white-on-blue "title bar" (the same
 * convention nano/Midnight Commander and similar terminal apps use) and
 * plain white body text with a quiet cyan accent, rather than a fully
 * monochrome look, so the message-source and border distinctions Phase
 * 1 established are still readable at a glance.
 *
 * Color palette confirmed against the REAL deployment target, not
 * assumed: TERM=linux on the actual Pi console reports COLORS=8,
 * COLOR_PAIRS=64 (the standard ANSI 8-color palette, not 256-color or
 * truecolor) - every color pair below stays within that. Deliberately
 * did NOT reach for real Unicode double-line box-drawing glyphs - the
 * console font in use (Lat15-Terminus, a codepage font, not a full
 * Unicode font) has no verified glyph coverage for those without a real
 * hardware round-trip to check, and every border in this file already
 * uses ncurses' own single-line ACS box() drawing, proven working on
 * this exact device since Phase 1.
 */
#define CP_STATUS   1 /* status "title bar": white text on blue - a
                          conventional terminal-app title-bar look */
#define CP_BORDER   2 /* panel borders: cyan on black */
#define CP_PEER_MSG 3 /* incoming (peer) messages: plain white on black */
#define CP_OWN_MSG  4 /* own sent messages: cyan on black - a quiet
                          distinction from peer messages, not a loud one */
#define CP_SYSTEM   5 /* system/event notices: white on black -
                          visually quieter than a real message */
#define CP_LOCKED   6 /* lock screen / danger state: red on black */
#define CP_INPUT    7 /* compose prompt: cyan on black */
#define CP_BANNER   8 /* splash/lock banner box: white on black */
#define CP_ACCENT   9 /* secondary accents (splash subtitle, WiFi
                          transient states): cyan on black */

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
    UI_MODE_SET_PIN_CONFIRM,
    UI_MODE_WIFI_SCANNING,
    UI_MODE_WIFI_SELECT,
    UI_MODE_WIFI_PASSWORD,
    UI_MODE_WIFI_CONNECTING
} ui_mode_t;

static ui_mode_t ui_mode = UI_MODE_NORMAL;
static int pin_configured = 0; /* cached lock_pin_exists(), see ui_init() */

/* The general masked-entry buffer: used for lock-PIN entry/setup AND
 * (further below) WiFi password entry - never both at once, since
 * ui_mode is mutually exclusive between those. Reused rather than
 * given a second buffer to avoid static-buffer proliferation for what
 * is mechanically the same "accumulate masked characters" behavior
 * either way. */
static char pin_entry_buf[LOCK_PIN_MAX_LEN + 1];
static size_t pin_entry_len = 0;
static char pin_first_entry_buf[LOCK_PIN_MAX_LEN + 1]; /* holds the first
    of two entries during UI_MODE_SET_PIN_NEW -> _CONFIRM */
static size_t pin_first_entry_len = 0;

static int wrong_attempt_count = 0;
static time_t next_allowed_check_time = 0;

#define UI_INACTIVITY_TIMEOUT_SECONDS 120
static time_t last_activity_time = 0;

/* --- WiFi setup screen (Week 4 Days 2-3 Part H) --------------------------
 *
 * Real design decisions, per Field WiFi and Network Resilience
 * Concepts.md - see wifi.h for the nmcli side:
 * - ENTRY POINT: Ctrl+W (ASCII 23), a second discoverable keybinding
 *   alongside Ctrl+L - only takes effect from UI_MODE_NORMAL (entering)
 *   or from within an active WIFI_* mode (cancelling back to normal).
 *   Deliberately does nothing while UI_MODE_LOCKED, same reasoning as
 *   Ctrl+L there - a locked screen shouldn't expose a path to change
 *   network settings without unlocking first.
 * - SESSION IMPACT: unlike the lock screen (which never touches
 *   connectivity at all), changing networks fundamentally requires
 *   dropping the current interface - some interruption here is
 *   genuinely unavoidable, not a design flaw to route around. This
 *   deliberately does NOT attempt a special graceful teardown of an
 *   active session first: client.c's existing reconnect-with-backoff
 *   loop (Week 3 Day 2, already tested) picks up cleanly once the new
 *   network is live, and PROTOCOL.md's seq_num already resets per
 *   session with no changes needed - adding a bespoke teardown path
 *   here for a rare, user-initiated operation would be real added
 *   complexity for no real benefit over what already exists.
 * - SLOW OPERATIONS OFF THE LOCK: wifi_scan()/wifi_connect() can each
 *   take several real seconds (a live network operation, not a local
 *   computation) - see ui_poll_line()'s pending_action handling, which
 *   runs these AFTER releasing ui_mutex, exactly the same "never hold
 *   the lock across something slow" discipline as session.c's
 *   send_mutex and this file's own earlier ui_mutex-starvation fix.
 */
static wifi_network wifi_scan_results[WIFI_SCAN_MAX_RESULTS];
static int wifi_scan_count = 0;
static char wifi_selected_ssid[WIFI_SSID_MAX];
static int wifi_selected_secured = 0;
static char wifi_pending_password[LOCK_PIN_MAX_LEN + 1]; /* copied out of
    pin_entry_buf (reused here as the general masked-entry buffer - see
    its own declaration comment) right before ui_mutex is released, so
    the deferred connect call in ui_poll_line() has it after unlocking */
static int wifi_list_header_row = -1; /* history_win row (its own
    coordinate space) where the "WiFi networks found" header was last
    drawn - entry i is at wifi_list_header_row + 1 + i. Used by the
    touch thread to map a tap back to a specific network - see this
    file's touch block comment for the known staleness edge case. */

typedef enum {
    UI_PENDING_NONE,
    UI_PENDING_WIFI_SCAN,
    UI_PENDING_WIFI_CONNECT
} ui_pending_action;

/* --- Touch (Week 4 Days 2-3, "Selection + wake" scope) -------------------
 *
 * Real decisions, per the user's explicit scope choice once physical
 * keyboards turned out not to be attached yet: keyboards remain the
 * only way to TYPE (compose a message, a PIN, a WiFi password - no
 * on-screen keyboard exists or is planned, same honest scope limit as
 * ui.h's touch/keyboard note already stated); touch adds three
 * SELECTION/gesture actions on top of that, confirmed against real
 * hardware (an ft5x06 controller, /dev/input/event1 on the units
 * tested - see touch.h for why that exact path is never hardcoded):
 * - LOCKED: a tap clears any lingering "Wrong PIN" message and
 *   redraws a clean PIN prompt - the closest honest analog this
 *   project has to "wake/dismiss a screensaver-equivalent"
 *   (ncurses UI Concepts.md's own suggested minimal touch scope),
 *   since there is no actual screen-dimming feature to wake from.
 * - UI_MODE_WIFI_SELECT: tapping a rendered network entry selects it,
 *   equivalent to typing its number and pressing Enter - see
 *   wifi_list_header_row's declaration for how a tap row maps back to
 *   an entry, and its documented staleness edge case.
 * - UI_MODE_NORMAL: tapping the UPPER half of history_win's rows
 *   "pauses" it (stops wrefresh()-ing on new content, reusing the
 *   exact suppress-refresh technique the lock screen already uses -
 *   see ui_add_history()); tapping the LOWER half "resumes" (reveals
 *   everything that accumulated while paused via touchwin()+
 *   wrefresh()). Deliberately NOT true arbitrary scrollback (which
 *   would need converting history_win from a plain window to a pad,
 *   a real architecture change) - "pause so new messages don't push
 *   away what you're reading, then catch up" covers the actual
 *   motivation for touch-scrolling on a small display without that
 *   rewrite, and is documented here as the honest, deliberate scope
 *   chosen instead of literal scrollback.
 *
 * THREADING: unlike the idle-input thread, this thread does NOT need
 * ui_start_idle_input()/ui_stop_idle_input()-style bracketing around
 * an active session - it never calls wgetch()/touches input_win's own
 * read state, only ui_mutex to update shared UI state, exactly like
 * the receiver thread's ui_add_history() calls already do safely. It
 * runs for the whole process lifetime once started in ui_init().
 */
static int touch_fd = -1;
static pthread_t touch_thread;
static volatile int touch_thread_running = 0;
static volatile int touch_thread_should_stop = 0;
static int history_paused = 0;

/* --- Message-pending LED flash + OLED background metrics --------------
 *
 * Both piggy-back on the touch thread's existing ~200ms poll loop
 * (touch_read_tap()'s own timeout drives it regardless of whether a tap
 * actually happens) rather than adding dedicated threads for either -
 * see ui.h's matching comments on ui_notify_message_pending()/
 * ui_set_oled_fd() for the full design reasoning.
 */
static volatile int message_pending_ack = 0;
static int flash_hw_fd = -1;      /* set per-call by
                                      ui_notify_message_pending() */
static int metrics_oled_fd = -1;  /* set once by ui_set_oled_fd() */

/* Toggle the flash roughly every 400ms (2 x the ~200ms loop period) -
 * fast enough to read as a deliberate "flash," slow enough not to look
 * like a malfunction. */
#define UI_FLASH_TOGGLE_ITERS 2

/* Refresh OLED metrics roughly every 30s (150 x ~200ms) - SSID/signal/
 * link-rate are not fast-changing values, and each refresh is a real
 * nmcli subprocess spawn (see wifi.c), not free; this is deliberately
 * much coarser than the flash toggle above. */
#define UI_METRICS_REFRESH_ITERS 150

/* Must be called with ui_mutex held. Replaces history_win's PHYSICAL
 * content with a locked banner, then STOPS refreshing history_win (see
 * ui_add_history() below) until unlock - real incoming messages keep
 * being written into history_win's off-screen buffer the whole time via
 * wprintw() there, regardless of lock state (the receiver thread calling
 * ui_add_history() never changes behavior based on lock state - see this
 * block's DECOUPLING note above), they just don't reach the physical
 * screen until wrefresh(history_win) happens again at unlock. */
/* --- Boot splash + lock-screen banner: shared box-drawing helpers ---
 *
 * Both draw a "+===...===+ / | text | / +===...===+" box, sized to the
 * text and centered, into whichever window is passed in (stdscr for the
 * boot splash, history_win for the lock screen). Deliberately plain
 * ASCII ('+', '=', '|') rather than Unicode box-drawing glyphs - see
 * this file's STYLING block comment for why. Width/columns computed
 * from the actual window/text at draw time (confirmed against real
 * hardware: TERM=linux + the deployed Lat15-Terminus24x12 font reports
 * 100 columns x 30 rows via `stty size` on /dev/tty1), not hardcoded
 * against an assumed screen size.
 */
static void ui_draw_hline(WINDOW *win, int row, int col, int width)
{
    char buf[96];
    int n = width;

    if (n < 2) {
        return;
    }
    if (n > (int)sizeof(buf) - 1) {
        n = (int)sizeof(buf) - 1;
    }
    memset(buf, '=', (size_t)n);
    buf[0] = '+';
    buf[n - 1] = '+';
    buf[n] = '\0';
    mvwprintw(win, row, col, "%s", buf);
}

static void ui_draw_centered(WINDOW *win, int row, int col, int width,
                              const char *text)
{
    char buf[96];
    int textlen = (int)strlen(text);
    int pad_total = width - 2 - textlen;
    int pad_left, pad_right;

    if (pad_total < 0) {
        pad_total = 0;
    }
    pad_left = pad_total / 2;
    pad_right = pad_total - pad_left;
    /* Guards against a caller passing an unexpectedly huge width -
     * "%*s" with a very large field width would still be memory-safe
     * (snprintf truncates to sizeof(buf)), but capping here keeps the
     * box actually looking like a box instead of silently truncating
     * one border edge off-screen on a narrow terminal. */
    if (pad_left > 40) {
        pad_left = 40;
    }
    if (pad_right > 40) {
        pad_right = 40;
    }
    snprintf(buf, sizeof(buf), "|%*s%s%*s|", pad_left, "", text,
             pad_right, "");
    mvwprintw(win, row, col, "%s", buf);
}

/* Shown once, full-screen on stdscr, before the panel layout exists -
 * purely cosmetic and blocking nothing real: this runs before any
 * thread (idle-input, touch, receiver) has started. 1.2s is a fixed,
 * deliberate delay meant to be READ, not a technical necessity - for
 * scale, Week 3 Day 4's own benchmark put a full mTLS handshake at
 * ~12-14ms, two orders of magnitude faster than this splash alone. */
static void show_splash(void)
{
    int box_width = 56;
    int col, row;
    const char *subtitle = "[ ENCRYPTED FIELD TERMINAL ]";

    if (box_width > COLS - 2) {
        box_width = COLS - 2;
    }
    if (box_width < 10) {
        return; /* pathologically narrow terminal - skip rather than
            risk garbled output; every other screen has its own margin
            logic and doesn't depend on this having run. */
    }
    col = (COLS - box_width) / 2;
    row = LINES / 2 - 3;
    if (row < 0) {
        row = 0;
    }

    clear();

    if (has_colors()) {
        attron(COLOR_PAIR(CP_BANNER));
    }
    ui_draw_hline(stdscr, row, col, box_width);
    ui_draw_centered(stdscr, row + 1, col, box_width, "S E C U R E L I N K");
    ui_draw_hline(stdscr, row + 2, col, box_width);
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_BANNER));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_ACCENT));
    }
    {
        int sublen = (int)strlen(subtitle);
        int subcol = col + (box_width - sublen) / 2;
        if (subcol < 0) {
            subcol = col;
        }
        mvprintw(row + 4, subcol, "%s", subtitle);
    }
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_ACCENT));
    }

    refresh();
    napms(1200);
    clear();
    refresh();
}

static void draw_locked_overlay_locked(void)
{
    int win_width = getmaxx(history_win);
    int box_width = win_width - 4;
    int col;

    werase(history_win);

    if (box_width > 40) {
        box_width = 40; /* a compact banner even on a wide screen,
            rather than stretching to fill it */
    }
    if (box_width < 10) {
        box_width = 10;
    }
    col = (win_width - box_width) / 2;
    if (col < 0) {
        col = 0;
    }

    wattron(history_win, COLOR_PAIR(CP_LOCKED));
    ui_draw_hline(history_win, 1, col, box_width);
    ui_draw_centered(history_win, 2, col, box_width, "L O C K E D");
    ui_draw_hline(history_win, 3, col, box_width);
    wattroff(history_win, COLOR_PAIR(CP_LOCKED));

    wattron(history_win, COLOR_PAIR(CP_SYSTEM));
    /* REAL BUG FOUND (2026-08-22, via live touch-gesture re-testing):
     * no trailing '\n' here left history_win's internal cursor sitting
     * mid-line, right after "unlock." - anything appended later via a
     * bare wprintw() (the WiFi-scan-results code, the only other
     * consumer of this window besides ui_add_history(), which always
     * includes its own trailing newline) silently concatenated onto
     * that same physical line instead of starting a fresh one. Fixed
     * by always ending on a clean line here too, regardless of what
     * runs next. */
    mvwprintw(history_win, 5, 1,
              "Messages are still being received normally in the "
              "background.\nEnter your PIN below and press Enter to "
              "unlock.\n");
    wattroff(history_win, COLOR_PAIR(CP_SYSTEM));

    wrefresh(history_win);
}

/* Mode-aware input-line redraw - replaces the old single-purpose
 * "redraw the compose line" function. Must be called with ui_mutex held. */
static void redraw_input_locked(void)
{
    size_t i;
    int cp = CP_INPUT; /* overridden below for sensitive-entry modes */
    int apply_uniform_color = 1; /* UI_MODE_NORMAL colors itself inline
        instead (a two-tone ">> " prompt vs. typed text) and skips the
        trailing mvwchgat below, which would otherwise flatten that
        back to one uniform color across the whole line. */

    werase(input_win);

    switch (ui_mode) {
    case UI_MODE_LOCKED:
        cp = CP_LOCKED;
        mvwprintw(input_win, 0, 0, "Enter PIN to unlock: ");
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        break;
    case UI_MODE_SET_PIN_NEW:
        cp = CP_LOCKED;
        mvwprintw(input_win, 0, 0, "Set a PIN (min %d chars): ",
                  LOCK_PIN_MIN_LEN);
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        break;
    case UI_MODE_SET_PIN_CONFIRM:
        cp = CP_LOCKED;
        mvwprintw(input_win, 0, 0, "Confirm PIN: ");
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        break;
    case UI_MODE_WIFI_SCANNING:
        cp = CP_ACCENT;
        mvwprintw(input_win, 0, 0,
                  "Scanning for WiFi networks... (Ctrl+W to cancel)");
        break;
    case UI_MODE_WIFI_SELECT:
        cp = CP_ACCENT;
        mvwprintw(input_win, 0, 0,
                  "Select network number (Ctrl+W to cancel): %s", input_buf);
        break;
    case UI_MODE_WIFI_PASSWORD:
        cp = CP_LOCKED;
        mvwprintw(input_win, 0, 0, "Password for %s (Ctrl+W to cancel): ",
                  wifi_selected_ssid);
        for (i = 0; i < pin_entry_len; i++) {
            waddch(input_win, '*');
        }
        break;
    case UI_MODE_WIFI_CONNECTING:
        cp = CP_ACCENT;
        mvwprintw(input_win, 0, 0, "Connecting to %s...",
                  wifi_selected_ssid);
        break;
    case UI_MODE_NORMAL:
    default:
        apply_uniform_color = 0;
        if (history_paused) {
            if (has_colors()) {
                wattron(input_win, COLOR_PAIR(CP_ACCENT));
            }
            mvwprintw(input_win, 0, 0,
                      "[PAUSED - tap lower half to resume]");
            if (has_colors()) {
                wattroff(input_win, COLOR_PAIR(CP_ACCENT));
            }
            waddch(input_win, ' ');
        }
        /* Two-tone compose prompt: the ">> " glyph itself is a
         * distinct color from the typed text after it - every other
         * mode above still applies one flat color to the whole line
         * via the trailing mvwchgat, this is the one deliberate
         * exception. */
        if (has_colors()) {
            wattron(input_win, COLOR_PAIR(CP_INPUT));
        }
        wprintw(input_win, ">> ");
        if (has_colors()) {
            wattroff(input_win, COLOR_PAIR(CP_INPUT));
        }
        wprintw(input_win, "%s", input_buf);
        break;
    }

    /* Applied to the whole line after drawing (rather than wrapping
     * every mvwprintw/waddch call individually above) - simpler, and
     * every character on the input line should share the same color
     * for a given mode anyway, masked PIN/password asterisks included.
     * Plain A_NORMAL, not A_BOLD - see this file's STYLING block
     * comment on the softer, standard-terminal color pass. Skipped for
     * UI_MODE_NORMAL - see above. */
    if (apply_uniform_color) {
        mvwchgat(input_win, 0, 0, -1, A_NORMAL, cp, NULL);
    }
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

    /* Color setup - see this file's STYLING block comment for the
     * palette rationale. has_colors() is checked defensively - a
     * terminal without color support (shouldn't happen with TERM=linux
     * on the real target, but conceivable elsewhere) just runs
     * monochrome rather than crashing or looking broken. */
    if (has_colors()) {
        start_color();
        init_pair(CP_STATUS, COLOR_WHITE, COLOR_BLUE);
        init_pair(CP_BORDER, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_PEER_MSG, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_OWN_MSG, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_SYSTEM, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_LOCKED, COLOR_RED, COLOR_BLACK);
        init_pair(CP_INPUT, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_BANNER, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_ACCENT, COLOR_CYAN, COLOR_BLACK);
    }

    /* Boot splash - see its own comment above for why this is safe to
     * run here (before any thread starts, before the panel windows
     * exist). Runs once per process start, i.e. once per boot given
     * this app's systemd unit (Restart=always) restarts the whole
     * process on any exit, not just this function. */
    show_splash();

    /* Layout: a 1-row status bar with a filled background (a "title
     * bar" look, via wbkgd() below) plus two bordered panels. Each
     * bordered panel is an OUTER window (box() only) with an INNER
     * derwin() for actual content - the standard ncurses pattern for a
     * border that survives scrolling: an inner derwin() physically
     * shares the same character grid as its parent's interior, so
     * refreshing just the inner window updates content without ever
     * touching, or needing to redraw, the border cells around it.
     * Every existing call site (ui_add_history(), redraw_input_locked(),
     * etc.) keeps using the SAME `history_win`/`input_win` names for
     * content - only what they're created FROM changed here. */
    status_win = newwin(1, COLS, 0, 0);

    history_border_win = newwin(LINES - 4, COLS, 1, 0);
    history_win = derwin(history_border_win, LINES - 6, COLS - 2, 1, 1);

    input_border_win = newwin(3, COLS, LINES - 3, 0);
    input_win = derwin(input_border_win, 1, COLS - 2, 1, 1);

    if (has_colors()) {
        wbkgd(status_win, COLOR_PAIR(CP_STATUS));
        wattron(history_border_win, COLOR_PAIR(CP_BORDER));
        wattron(input_border_win, COLOR_PAIR(CP_BORDER));
    }
    box(history_border_win, 0, 0);
    box(input_border_win, 0, 0);
    if (has_colors()) {
        wattroff(history_border_win, COLOR_PAIR(CP_BORDER));
        wattroff(input_border_win, COLOR_PAIR(CP_BORDER));
    }
    wrefresh(history_border_win);
    wrefresh(input_border_win);

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
    {
        /* Replay recent persisted chat history (see msglog.h) so a
         * reboot doesn't present a blank, context-free screen - each
         * line is ALREADY formatted with its own embedded timestamp
         * (msglog_append()'s own "[YYYY-MM-DD HH:MM:SS] who: text"),
         * so this deliberately writes directly into history_win rather
         * than going through ui_add_history() (which would prepend a
         * SECOND, current-time timestamp on top of the log's own
         * historical one - wrong). Written into the buffer the same
         * way real live content is (see ui_add_history()'s DECOUPLING
         * note) - it becomes visible on wrefresh() below (if unlocked)
         * or stays queued behind the lock overlay (if locked), exactly
         * like any other pre-existing history would. */
        char recent[20][MSGLOG_LINE_MAX];
        int n = msglog_load_recent(recent,
                                     (int)(sizeof(recent) / sizeof(recent[0])));
        if (n > 0) {
            int i;
            wattron(history_win, COLOR_PAIR(CP_SYSTEM));
            wprintw(history_win, "--- previous session history ---\n");
            for (i = 0; i < n; i++) {
                wprintw(history_win, "%s\n", recent[i]);
            }
            wprintw(history_win, "--- end of previous history ---\n");
            wattroff(history_win, COLOR_PAIR(CP_SYSTEM));
        }
    }
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

    /* Started once here, for the whole process lifetime - unlike the
     * idle-input thread, no bracketing around sessions is needed (see
     * this file's touch block comment). Silently does nothing if no
     * touchscreen is attached (touch_open() returning -1). */
    ui_start_touch();
}

void ui_set_status(const char *status_text)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    /* werase() fills with status_win's background attribute, set once
     * in ui_init() via wbkgd() - CP_STATUS, giving the whole row a
     * filled "title bar" look rather than just colored text on a
     * black background. */
    werase(status_win);
    /* A persistent brand prefix, not just the raw status text - the
     * status bar is the one thing visible in every mode (locked,
     * mid-WiFi-setup, normal), so this is the actual "always-on"
     * identity/chrome of the whole neon look, not just a one-time
     * splash. */
    mvwprintw(status_win, 0, 1, "SECURELINK :: %s",
              status_text != NULL ? status_text : "");
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
    {
        /* Color by source: NULL prefix is a system/event notice (quiet
         * cyan, no bold); "you" (session.c's own convention for the
         * local user's sent messages) gets a distinct color from an
         * incoming peer message (any other non-NULL prefix, i.e. the
         * peer_label session.c passes) - makes it possible to tell at
         * a glance who said what without reading every line. */
        int cp = CP_SYSTEM;
        char ts_buf[12]; /* "[HH:MM:SS] " + NUL */
        time_t now = time(NULL);
        struct tm tm_now;
#ifdef _WIN32
        localtime_s(&tm_now, &now);
#else
        localtime_r(&now, &tm_now);
#endif
        strftime(ts_buf, sizeof(ts_buf), "[%H:%M:%S] ", &tm_now);

        if (prefix != NULL) {
            cp = (strcmp(prefix, "you") == 0) ? CP_OWN_MSG : CP_PEER_MSG;
        }
        /* Timestamp itself always in the quiet system color, regardless
         * of the line's own source color - it's metadata about the
         * line, not part of what was actually said. Local wall-clock
         * time only (this device's own clock at receive/send time) -
         * deliberately NOT a value carried on the wire (see
         * PROTOCOL.md's PONG entry for the same reasoning applied to
         * RTT): two devices' clocks aren't guaranteed synchronized
         * (Raspberry Pis have no hardware RTC - see Field WiFi and
         * Network Resilience Concepts.md), so a wire-carried timestamp
         * could be actively misleading across devices in a way a
         * purely local one never is. */
        wattron(history_win, COLOR_PAIR(CP_SYSTEM));
        wprintw(history_win, "%s", ts_buf);
        wattroff(history_win, COLOR_PAIR(CP_SYSTEM));

        wattron(history_win, COLOR_PAIR(cp));
        if (prefix != NULL) {
            wprintw(history_win, "%s: %s\n", prefix, text != NULL ? text : "");
        } else {
            wprintw(history_win, "%s\n", text != NULL ? text : "");
        }
        wattroff(history_win, COLOR_PAIR(cp));
    }
    /* Always write into history_win's buffer (above), regardless of lock
     * or pause state - see this file's lock-screen block comment's
     * DECOUPLING note: the receiver thread calling this must never
     * behave differently based on UI state. Only the PHYSICAL screen
     * update is gated: while locked, skip wrefresh() so the
     * accumulating real content stays invisible behind the lock overlay
     * (drawn once, at lock time) until unlock explicitly reveals it -
     * and likewise while history_paused (see this file's touch block
     * comment), so a deliberate "hold still, I'm reading this" tap
     * isn't immediately undone by the next incoming message. */
    if (ui_mode != UI_MODE_LOCKED && !history_paused) {
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
        ui_pending_action pending_action = UI_PENDING_NONE; /* same idea
            as pending_history_msg, but for a slow (real seconds, a live
            network operation) wifi_scan()/wifi_connect() call that must
            never run while ui_mutex is held - see this file's WiFi
            block comment's SLOW OPERATIONS note */
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

            if (ch == 12 && ui_mode == UI_MODE_NORMAL) {
                /* Ctrl+L (ASCII 12) - the lock screen's single
                 * discoverable entry point, doing double duty per this
                 * file's lock-screen block comment. Only takes effect
                 * from UI_MODE_NORMAL - restricted here (rather than
                 * the earlier, looser "anything but LOCKED") so it
                 * can't jump into locking out from the middle of a
                 * WiFi-setup flow either; pressed from any other mode
                 * it's simply not one of that mode's own recognized
                 * keys, a harmless no-op. */
                if (pin_configured) {
                    ui_mode = UI_MODE_LOCKED;
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                    draw_locked_overlay_locked();
                } else {
                    ui_mode = UI_MODE_SET_PIN_NEW;
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                }
                redraw_input_locked();
            } else if (ch == 23 &&
                       (ui_mode == UI_MODE_NORMAL ||
                        ui_mode == UI_MODE_WIFI_SCANNING ||
                        ui_mode == UI_MODE_WIFI_SELECT ||
                        ui_mode == UI_MODE_WIFI_PASSWORD ||
                        ui_mode == UI_MODE_WIFI_CONNECTING)) {
                /* Ctrl+W (ASCII 23) - the WiFi setup screen's single
                 * discoverable entry point (see this file's WiFi block
                 * comment), doubling as "cancel" when already
                 * somewhere in that flow. Deliberately excludes
                 * UI_MODE_LOCKED and the PIN-setup modes - same
                 * "don't jump modes mid-flow" reasoning as Ctrl+L
                 * above, plus a locked screen shouldn't expose a path
                 * to touch network settings without unlocking first. */
                if (ui_mode == UI_MODE_NORMAL) {
                    ui_mode = UI_MODE_WIFI_SCANNING;
                    pending_action = UI_PENDING_WIFI_SCAN;
                } else {
                    ui_mode = UI_MODE_NORMAL;
                    input_len = 0;
                    input_buf[0] = '\0';
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
            } else if (ui_mode == UI_MODE_WIFI_SELECT) {
                /* Reuses input_buf (the normal, UNMASKED compose
                 * buffer) rather than pin_entry_buf - a network list
                 * index isn't sensitive, and this keeps the "masked
                 * buffer" naming honest for what actually goes in it
                 * elsewhere. Digits only, not general printable ASCII -
                 * a tighter, more honest restriction than the compose
                 * line's since only a number is ever meaningful here. */
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    int idx = atoi(input_buf) - 1; /* shown 1-based to
                        the person typing, stored 0-based internally */
                    input_len = 0;
                    input_buf[0] = '\0';
                    if (idx < 0 || idx >= wifi_scan_count) {
                        werase(input_win);
                        mvwprintw(input_win, 0, 0,
                                  "Invalid selection - try again "
                                  "(Ctrl+W to cancel):");
                        wrefresh(input_win);
                    } else {
                        snprintf(wifi_selected_ssid,
                                  sizeof(wifi_selected_ssid), "%s",
                                  wifi_scan_results[idx].ssid);
                        wifi_selected_secured =
                            wifi_scan_results[idx].secured;
                        if (wifi_selected_secured) {
                            ui_mode = UI_MODE_WIFI_PASSWORD;
                            pin_entry_len = 0;
                            pin_entry_buf[0] = '\0';
                        } else {
                            ui_mode = UI_MODE_WIFI_CONNECTING;
                            wifi_pending_password[0] = '\0';
                            pending_action = UI_PENDING_WIFI_CONNECT;
                        }
                        redraw_input_locked();
                    }
                } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                    if (input_len > 0) {
                        input_len--;
                        input_buf[input_len] = '\0';
                        redraw_input_locked();
                    }
                } else if (ch >= '0' && ch <= '9') {
                    if (input_len + 1 < sizeof(input_buf)) {
                        input_buf[input_len++] = (char)ch;
                        input_buf[input_len] = '\0';
                        redraw_input_locked();
                    }
                }
            } else if (ui_mode == UI_MODE_WIFI_PASSWORD) {
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    snprintf(wifi_pending_password,
                              sizeof(wifi_pending_password), "%s",
                              pin_entry_buf);
                    pin_entry_len = 0;
                    pin_entry_buf[0] = '\0';
                    ui_mode = UI_MODE_WIFI_CONNECTING;
                    pending_action = UI_PENDING_WIFI_CONNECT;
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
            /* UI_MODE_WIFI_SCANNING / UI_MODE_WIFI_CONNECTING: transient
             * states with no direct key handling of their own beyond
             * the Ctrl+W cancel above - nothing meaningful to type
             * while a scan/connect is actually in progress (see this
             * loop's pending_action handling just below, which runs
             * them synchronously to completion before this function
             * returns - see this file's WiFi block comment). */

            pthread_mutex_unlock(&ui_mutex);

            if (pending_history_msg != NULL) {
                ui_add_history(NULL, pending_history_msg);
            }

            if (pending_action == UI_PENDING_WIFI_SCAN) {
                int n = wifi_scan(wifi_scan_results, WIFI_SCAN_MAX_RESULTS);
                wifi_scan_count = (n > 0) ? n : 0;

                pthread_mutex_lock(&ui_mutex);
                if (wifi_scan_count > 0) {
                    int i;
                    /* Remember exactly where (within history_win's own
                     * row coordinates) the list gets drawn, so a
                     * touch tap can be mapped back to a specific
                     * entry - see this file's touch block comment for
                     * the known edge case (an incoming chat message
                     * scrolling history_win further while this list
                     * is showing would make this stale). */
                    wifi_list_header_row = getcury(history_win);
                    wprintw(history_win,
                            "WiFi networks found (Ctrl+W to cancel):\n");
                    for (i = 0; i < wifi_scan_count; i++) {
                        wprintw(history_win, "  %d) %s%s\n", i + 1,
                                wifi_scan_results[i].ssid,
                                wifi_scan_results[i].secured
                                    ? " (secured)" : " (open)");
                    }
                    wrefresh(history_win);
                    ui_mode = UI_MODE_WIFI_SELECT;
                    input_len = 0;
                    input_buf[0] = '\0';
                } else {
                    ui_mode = UI_MODE_NORMAL;
                }
                redraw_input_locked();
                pthread_mutex_unlock(&ui_mutex);

                if (wifi_scan_count <= 0) {
                    ui_add_history(NULL,
                        "WiFi scan found no networks (or nmcli failed) "
                        "- Ctrl+W to try again.");
                }
            } else if (pending_action == UI_PENDING_WIFI_CONNECT) {
                char errbuf[256];
                char ssid_copy[WIFI_SSID_MAX];
                int rc;

                snprintf(ssid_copy, sizeof(ssid_copy), "%s",
                          wifi_selected_ssid);
                rc = wifi_connect(wifi_selected_ssid,
                                    wifi_pending_password[0] != '\0'
                                        ? wifi_pending_password : NULL,
                                    errbuf, sizeof(errbuf));
                /* Zero the password out of memory as soon as it's no
                 * longer needed, rather than leaving a stale copy
                 * sitting in a static buffer for the rest of the
                 * process's life. */
                memset(wifi_pending_password, 0,
                       sizeof(wifi_pending_password));

                pthread_mutex_lock(&ui_mutex);
                ui_mode = UI_MODE_NORMAL;
                redraw_input_locked();
                pthread_mutex_unlock(&ui_mutex);

                if (rc == 0) {
                    ui_add_historyf(NULL,
                        "Connected to WiFi network \"%s\".", ssid_copy);
                } else {
                    ui_add_historyf(NULL,
                        "Failed to connect to \"%s\": %s", ssid_copy,
                        errbuf);
                }
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
    /* Belt-and-suspenders: if the idle thread is somehow still running
     * (a caller forgot to bracket a session with
     * ui_stop_idle_input()/ui_start_idle_input(), or is exiting
     * abnormally), stop it before endwin() rather than leaving it
     * reading from a window that's about to be torn down. Same
     * reasoning for the touch thread, which normally only ever gets
     * stopped here anyway (see ui_start_touch()'s comment). */
    ui_stop_idle_input();
    ui_stop_touch();
    if (ui_active) {
        ui_active = 0;
        endwin();
    }
}

/* --- Idle input - see ui.h's "IDLE INPUT" comment for the full why.
 * Runs ui_poll_line() on a dedicated thread whenever no session is
 * active, so lock-screen interaction (Ctrl+L, PIN entry, first-time
 * PIN setup) works even while client.c/server.c are disconnected or
 * blocked in accept()/a reconnect backoff sleep. --- */
static pthread_t idle_thread;
static volatile int idle_thread_running = 0;
static volatile int idle_thread_should_stop = 0;

/* How often the idle thread runs wifi_has_connectivity() to drive the
 * "no network found" prompt (Field WiFi and Network Resilience
 * Concepts.md) - a real subprocess spawn each time (see wifi.c), not
 * free, so this is deliberately much coarser than the 200ms input-poll
 * granularity rather than run on every idle-loop iteration. Only ever
 * WRITES the status bar when there's genuinely no connectivity -
 * leaves it alone otherwise, so it doesn't fight with client.c's/
 * server.c's own more specific status updates ("Disconnected -
 * retrying in Ns...", "Listening on port...") for ownership of that
 * line on every normal cycle; the two can still occasionally race for
 * a moment right at a state transition, an accepted minor cosmetic
 * tradeoff, not a functional one. */
#define UI_CONNECTIVITY_CHECK_SECONDS 15

static void *idle_input_thread_main(void *arg)
{
    char dummy[OUTBOX_MSG_MAX_LEN]; /* sized for a real queued message,
        not just a throwaway buffer - see the UI_POLL_LINE handling
        below, which now actually queues this instead of discarding it */
    time_t last_connectivity_check = 0;
    (void)arg;

    while (!idle_thread_should_stop) {
        ui_poll_result pr = ui_poll_line(dummy, sizeof(dummy), 200);
        if (pr == UI_POLL_LINE) {
            /* Something was typed and Enter pressed, but there's no
             * active session to send it through - queue it (see
             * outbox.h) rather than silently dropping it, so it goes
             * out automatically the moment a session actually starts
             * (session.c drains the outbox right after connecting). */
            if (outbox_enqueue(dummy) == 0) {
                ui_add_history(NULL, "(not connected - message queued, "
                                      "will send once connected)");
            } else {
                ui_add_history(NULL, "(not connected - queue is full, "
                                      "message NOT sent)");
            }
        }
        /* UI_POLL_TIMEOUT: normal, keep looping. UI_POLL_QUIT: never
         * returned by the real ncurses ui_poll_line() - see ui.h. */

        if (difftime(time(NULL), last_connectivity_check) >=
                UI_CONNECTIVITY_CHECK_SECONDS) {
            last_connectivity_check = time(NULL);
            if (!wifi_has_connectivity()) {
                ui_set_status("No network found - press Ctrl+W to set "
                               "up WiFi.");
            }
        }
    }
    return NULL;
}

void ui_start_idle_input(void)
{
    if (!ui_active || idle_thread_running) {
        return;
    }
    idle_thread_should_stop = 0;
    if (pthread_create(&idle_thread, NULL, idle_input_thread_main, NULL)
            == 0) {
        idle_thread_running = 1;
    }
}

void ui_stop_idle_input(void)
{
    if (!idle_thread_running) {
        return;
    }
    idle_thread_should_stop = 1;
    pthread_join(idle_thread, NULL);
    idle_thread_running = 0;
}

/* --- Touch thread - see this file's touch block comment above for the
 * three gestures implemented and why this thread needs no
 * start/stop bracketing around sessions the way the idle-input
 * thread does. --- */

/* Must be called with ui_mutex held. tap_row/tap_col are already
 * screen-relative (0..LINES-1 / 0..COLS-1). */
static void handle_tap_locked(int tap_row, int tap_col)
{
    (void)tap_col; /* every gesture here is row-based (which window,
        which half) - kept as a parameter rather than discarding the
        information at the call site, for a future column-sensitive
        gesture. */

    if (ui_mode == UI_MODE_LOCKED) {
        /* Clears any lingering "Wrong PIN" message and redraws a
         * clean prompt - see this file's touch block comment for why
         * this is the honest analog to "wake/dismiss a screensaver". */
        redraw_input_locked();
    } else if (ui_mode == UI_MODE_WIFI_SELECT) {
        /* history_win's CONTENT starts at absolute screen row 2 now
         * (row 0 = status bar, row 1 = history_border_win's top border
         * edge, row 2 = first content row) - see ui_init()'s STYLING
         * comment for the bordered-panel layout this offset comes
         * from. */
        int history_row = tap_row - 2;
        int idx = history_row - (wifi_list_header_row + 1);

        if (wifi_list_header_row >= 0 && idx >= 0 &&
            idx < wifi_scan_count) {
            snprintf(wifi_selected_ssid, sizeof(wifi_selected_ssid), "%s",
                      wifi_scan_results[idx].ssid);
            wifi_selected_secured = wifi_scan_results[idx].secured;
            input_len = 0;
            input_buf[0] = '\0';
            pin_entry_len = 0;
            pin_entry_buf[0] = '\0';
            /* Lands on the password prompt even for an open network,
             * rather than kicking off the connect immediately - this
             * thread has no access to ui_poll_line()'s "pending
             * action, run after releasing ui_mutex" mechanism (that
             * machinery is scoped to a single call's local
             * variables), and wifi_connect() already treats an empty
             * password the same as "no password" - one extra Enter
             * press for the open-network case is a small, honest
             * price for not duplicating that deferred-call machinery
             * here for a rare case. */
            ui_mode = UI_MODE_WIFI_PASSWORD;
            redraw_input_locked();
        }
    } else if (ui_mode == UI_MODE_NORMAL) {
        /* Same border-offset reasoning as the WIFI_SELECT branch above. */
        int history_height = LINES - 6;
        int history_row = tap_row - 2;

        if (history_row >= 0 && history_row < history_height) {
            if (history_row < history_height / 2) {
                if (!history_paused) {
                    history_paused = 1;
                    redraw_input_locked();
                }
            } else if (history_paused) {
                history_paused = 0;
                /* Reveal everything that accumulated while paused -
                 * touchwin() forces a full redraw, same reasoning as
                 * the lock screen's unlock path: ncurses' normal
                 * diff-based refresh can miss content that changed
                 * while this window wasn't the one being refreshed. */
                touchwin(history_win);
                wrefresh(history_win);
                redraw_input_locked();
            }
        }
    }
    /* Other modes (WIFI_SCANNING, WIFI_PASSWORD, WIFI_CONNECTING,
     * SET_PIN_NEW, SET_PIN_CONFIRM): no touch gesture defined - a tap
     * during one of these transient/sensitive-entry states is simply
     * ignored rather than guessed at. */
}

/* Draws WiFi SSID/signal/link-rate and a basic connectivity indicator
 * into the OLED's framebuffer, BELOW whatever session.c/client.c/
 * server.c's own hw_oled_draw_text() calls already own (lines 0-1: role
 * + status/message-preview - see hw_oled.h's line-numbering contract).
 * Does NOT hold ui_mutex - this only touches the OLED (a completely
 * separate device from the touchscreen ncurses manages) via hw_oled.h's
 * own already-thread-safe-by-construction fd-based API (no shared
 * mutable state of its own), same reasoning as the RGB LED calls
 * elsewhere in this file needing no locking either. */
static void refresh_oled_metrics(void)
{
    wifi_link_info info;
    /* Sized to comfortably hold the longest possible formatted string
     * (a WIFI_SSID_MAX-1 (63) char SSID plus its "WiFi: " prefix), not
     * HW_OLED_COLS+1 - hw_oled_draw_text() already truncates safely to
     * the display's own 21-char width (see hw_oled.h), so there's
     * nothing to gain from ALSO truncating here at snprintf() time,
     * and doing so was tripping -Wformat-truncation for no real benefit
     * (this project holds a zero-warnings bar). */
    char line[96];

    if (metrics_oled_fd < 0) {
        return;
    }

    if (wifi_get_link_info(&info) == 0) {
        snprintf(line, sizeof(line), "WiFi: %s", info.ssid);
        hw_oled_draw_text(metrics_oled_fd, 3, line);
        snprintf(line, sizeof(line), "Sig %d%%  %s",
                  info.signal_percent, info.rate);
        hw_oled_draw_text(metrics_oled_fd, 4, line);
    } else {
        hw_oled_draw_text(metrics_oled_fd, 3, "WiFi: (none)");
        hw_oled_draw_text(metrics_oled_fd, 4, "");
    }

    /* wifi_has_connectivity() already exists (the "no network found"
     * prompt on the main UI uses it too, see the idle thread above) -
     * reused rather than re-implementing an equivalent check here. */
    hw_oled_draw_text(metrics_oled_fd, 5,
                       wifi_has_connectivity() ? "Net: OK" : "Net: DOWN");

    hw_oled_display(metrics_oled_fd);
}

static void *touch_thread_main(void *arg)
{
    int flash_toggle_counter = 0;
    int flash_led_on = 0;
    int metrics_counter = UI_METRICS_REFRESH_ITERS; /* draw once
        immediately on the first loop iteration, rather than waiting a
        full 30s for the first-ever refresh */
    (void)arg;

    while (!touch_thread_should_stop) {
        touch_point pt;
        int rc = touch_read_tap(touch_fd, &pt, 200);

        /* Message-pending flash toggle - runs every iteration
         * regardless of whether a tap happened, independent of the
         * rc==1/rc<0 handling below. See ui.h's
         * ui_notify_message_pending() comment for why HW_STATUS_ALERT
         * (magenta) vs. off, and why a real tap (below) always restores
         * HW_STATUS_CONNECTED specifically. */
        if (message_pending_ack && flash_hw_fd >= 0) {
            flash_toggle_counter++;
            if (flash_toggle_counter >= UI_FLASH_TOGGLE_ITERS) {
                flash_toggle_counter = 0;
                flash_led_on = !flash_led_on;
                if (flash_led_on) {
                    hw_expansion_set_status_color(flash_hw_fd,
                                                   HW_STATUS_ALERT);
                } else {
                    hw_expansion_set_led_mode(flash_hw_fd, HW_LED_MODE_OFF);
                }
            }
        }

        /* OLED background metrics refresh - same "every iteration,
         * independent of taps" shape as the flash toggle above, just on
         * a much coarser interval. */
        metrics_counter++;
        if (metrics_counter >= UI_METRICS_REFRESH_ITERS) {
            metrics_counter = 0;
            refresh_oled_metrics();
        }

        if (rc == 1) {
            int tap_row = (int)(pt.y * LINES);
            int tap_col = (int)(pt.x * COLS);

            if (tap_row < 0) {
                tap_row = 0;
            } else if (tap_row >= LINES) {
                tap_row = LINES - 1;
            }
            if (tap_col < 0) {
                tap_col = 0;
            } else if (tap_col >= COLS) {
                tap_col = COLS - 1;
            }

            pthread_mutex_lock(&ui_mutex);
            handle_tap_locked(tap_row, tap_col);
            pthread_mutex_unlock(&ui_mutex);

            /* ANY tap acknowledges a pending message flash, not just a
             * tap on the message itself - see ui.h's comment. */
            if (message_pending_ack) {
                message_pending_ack = 0;
                flash_toggle_counter = 0;
                flash_led_on = 0;
                if (flash_hw_fd >= 0) {
                    hw_expansion_set_led_mode(flash_hw_fd,
                                               HW_LED_MODE_MANUAL_RGB);
                    hw_expansion_set_status_color(flash_hw_fd,
                                                   HW_STATUS_CONNECTED);
                }
            }
        } else if (rc < 0) {
            /* Device error (e.g. unplugged) - stop trying rather than
             * spin on a broken fd. */
            break;
        }
    }
    return NULL;
}

void ui_start_touch(void)
{
    if (!ui_active || touch_thread_running) {
        return;
    }
    touch_fd = touch_open();
    if (touch_fd < 0) {
        return; /* no touchscreen attached - non-fatal, see touch.h */
    }
    touch_thread_should_stop = 0;
    if (pthread_create(&touch_thread, NULL, touch_thread_main, NULL) == 0) {
        touch_thread_running = 1;
    } else {
        touch_close(touch_fd);
        touch_fd = -1;
    }
}

void ui_stop_touch(void)
{
    if (!touch_thread_running) {
        return;
    }
    touch_thread_should_stop = 1;
    pthread_join(touch_thread, NULL);
    touch_thread_running = 0;
    touch_close(touch_fd);
    touch_fd = -1;
}

void ui_notify_message_pending(int hw_fd)
{
    /* Deliberate honest limit: the flash toggle and its acknowledgment
     * are entirely driven by the touch thread (see touch_thread_main
     * above), so if no touchscreen is attached at all (touch_open()
     * failed in ui_start_touch(), touch_thread_running stays 0), a
     * flash could be requested here but would never actually toggle or
     * ever be acknowledgeable. Not worth a separate fallback thread
     * just for that - this project's actual deployed hardware always
     * has the touchscreen attached. */
    flash_hw_fd = hw_fd;
    message_pending_ack = 1;
}

void ui_set_oled_fd(int fd)
{
    metrics_oled_fd = fd;
}

void ui_report_rtt(int rtt_ms)
{
    char line[32];

    if (metrics_oled_fd < 0) {
        return;
    }
    /* Written immediately rather than waiting for
     * refresh_oled_metrics()'s own ~30s timer - this already only
     * arrives roughly every SESSION_PING_INTERVAL_SECONDS (session.c),
     * so there's no risk of hammering the OLED with excessive I2C
     * traffic, and a fresh RTT sample is more useful shown promptly
     * than held back to line up with an unrelated refresh cycle. */
    snprintf(line, sizeof(line), "RTT: %dms", rtt_ms);
    hw_oled_draw_text(metrics_oled_fd, 6, line);
    hw_oled_display(metrics_oled_fd);
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

/* No lock screen exists on this fallback path at all (see ui.h's top
 * comment - it's a Linux/ncurses-only UI feature), so there's nothing
 * for idle input polling to service here - no-ops, present only so
 * client.c/server.c can call these unconditionally on either platform. */
void ui_start_idle_input(void)
{
}

void ui_stop_idle_input(void)
{
}

/* No touchscreen exists on this project's Windows dev machine - see
 * touch.h. No-ops, present only so client.c/server.c can call these
 * unconditionally on either platform. */
void ui_start_touch(void)
{
}

void ui_stop_touch(void)
{
}

/* No case RGB LEDs or OLED exist on this project's Windows dev machine -
 * see hw_expansion.h/hw_oled.h. No-ops, present only so
 * client.c/server.c/session.c can call these unconditionally on either
 * platform. */
void ui_notify_message_pending(int hw_fd)
{
    (void)hw_fd;
}

void ui_set_oled_fd(int fd)
{
    (void)fd;
}

void ui_report_rtt(int rtt_ms)
{
    (void)rtt_ms;
}

#endif /* __linux__ */

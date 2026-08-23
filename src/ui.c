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
/* Only for session_perform_local_destroy() - see its own declaration
 * comment in session.h for why this file needs it too (the "/destroy"
 * command's offline case, in idle_input_thread_main() below). A
 * pragmatic, narrow exception to this file otherwise having no
 * dependency on session.h/session.c - not a broader layering change. */
#include "session.h"

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
static WINDOW *history_win = NULL;        /* a PAD (newpad()), not a
    plain window - holds real, retained scrollback (see this file's
    touch block comment for why this changed from an earlier derwin()).
    All existing call sites keep using this name for writing content
    (wprintw() etc. work identically on a pad); only the "make it
    visible on screen" step changed - see refresh_history_viewport_locked()
    below, which replaces every old direct wrefresh(history_win) call. */
static WINDOW *lock_overlay_win = NULL;   /* plain window, same screen
    rectangle as history_win's viewport (see HISTORY_VIEWPORT_TOP_ROW/
    HISTORY_VIEWPORT_LEFT_COL below) - shown INSTEAD OF prefresh()-ing
    the pad while locked, so the lock banner never has to erase or
    otherwise touch the pad's actual retained content (a real bug in
    the pre-pad design - see this file's touch block comment). */
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
#define CP_TIMESTAMP 10 /* the "[HH:MM:SS] " prefix on every history
                          line: blue on black - 2026-08-22, split out
                          from CP_SYSTEM specifically so timestamps read
                          as quiet metadata distinct from the system
                          notices that follow them, per direct request
                          to increase color differentiation between
                          output "kinds." */
#define CP_ERROR    11 /* errors/failures: red on black - see
                          ui_add_error()/ui_add_errorf(), the new
                          sibling to ui_add_history()/ui_add_historyf()
                          for anything that represents a real failure
                          (socket/handshake/send errors, rejected
                          certs, etc.), as opposed to routine status
                          notices (still CP_SYSTEM). Same red as
                          CP_LOCKED - never shown in the same place at
                          the same time (that's a dedicated overlay
                          window, this is a history line color), and
                          "red = something's wrong" is the same
                          intuitive meaning in both places. */

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
static long wifi_list_header_row = -1; /* ABSOLUTE line index (same
    numbering as history_total_lines below, NOT a pad-relative row -
    see this file's touch block comment for why that distinction now
    matters) where the "WiFi networks found" header was last drawn -
    entry i is at wifi_list_header_row + 1 + i. Used by the touch
    thread to map a tap back to a specific network. */

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
 *
 * UI_MODE_NORMAL deliberately has NO touch gesture (as of the
 * 2026-08-22 rewrite) - an earlier version used tapping the upper/lower
 * half of history_win to scroll/pause scrollback, but real testing
 * surfaced touch-hardware reliability problems (taps not reliably
 * reaching the kernel at all in some sessions - see TESTING.md), on top
 * of small touch targets already being a worse fit than dedicated keys
 * for "hold still and pick a spot." Scrollback navigation moved to
 * UP/DOWN arrow keys instead (ui_poll_line()'s UI_MODE_NORMAL branch,
 * via scroll_history_locked()) - see history_win's declaration comment:
 * it's still a real PAD holding up to HISTORY_PAD_LINES of retained
 * history, just driven by keyboard input now, not touch.
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

/* --- Real scrollback state (history_win is a PAD - see its own
 * declaration comment) -----------------------------------------------
 *
 * history_total_lines counts every line EVER written, even past
 * HISTORY_PAD_LINES (once the pad itself internally scrolls and starts
 * discarding its own oldest rows) - this is what makes it safe to use
 * as a stable, ever-increasing coordinate for view position and for
 * wifi_list_header_row above, unlike a raw pad row (getcury()), which
 * ncurses pins back once the pad's own internal scrolling kicks in and
 * would otherwise silently go stale/wrong the moment that happens.
 *
 * history_view_line is the absolute line index (same numbering)
 * currently shown at the TOP of the viewport. history_following==1
 * means "keep it pinned to the live/bottom position, recomputed on
 * every write" (the normal, default state); pressing Up
 * (scroll_history_locked()) sets history_following to 0 and pins
 * history_view_line where the user scrolled to, so new incoming
 * messages keep accumulating in the pad without visually yanking their
 * view.
 */
#define HISTORY_PAD_LINES 3000
static long history_total_lines = 0;
static long history_view_line = 0;
static int history_following = 1;

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
static volatile int hw_link_connected = 0; /* kept in sync by
    ui_set_link_state(), called from client.c/server.c at the same
    moments they call hw_expansion_set_status_color() with
    HW_STATUS_CONNECTED/HW_STATUS_DISCONNECTED - see ui.h's comment.
    Starts 0 (disconnected) since ui_init() always runs before any
    connection attempt. */

/* Toggle the flash roughly every 400ms (2 x the ~200ms loop period) -
 * fast enough to read as a deliberate "flash," slow enough not to look
 * like a malfunction. */
#define UI_FLASH_TOGGLE_ITERS 2

/* Refresh OLED metrics roughly every 30s (150 x ~200ms) - SSID/signal/
 * link-rate are not fast-changing values, and each refresh is a real
 * nmcli subprocess spawn (see wifi.c), not free; this is deliberately
 * much coarser than the flash toggle above. */
#define UI_METRICS_REFRESH_ITERS 150

/* Clears message_pending_ack and restores the LED to the current base
 * connection color (green if hw_link_connected, red otherwise - see
 * ui_set_link_state()) - shared by touch_thread_main() (a real tap - see
 * handle_tap_locked()'s caller) and ui_poll_line() (a real keystroke -
 * see its UI_MODE_NORMAL branch). Both count as "the device was used" as
 * of the 2026-08-22 rewrite: touch alone used to be the only way to clear
 * this, which meant a genuine touch-hardware fault (see this file's touch
 * block comment) could leave the LED flashing indefinitely with no way to
 * silence it short of a physical keypress the flash indicator itself
 * doesn't require - now either input method clears it, so a working
 * keyboard is always enough on its own regardless of touch's health.
 * Callable from either the touch thread or the thread running
 * ui_poll_line() (the idle-input thread or session.c's own caller) since
 * hw_expansion's fd-based calls are thread-safe by construction (no
 * shared mutable state of their own - same reasoning already applied to
 * every other RGB LED call in this file) and message_pending_ack/
 * hw_link_connected are both `volatile int`, not requiring ui_mutex. */
static void clear_message_pending_flash(void)
{
    if (!message_pending_ack) {
        return;
    }
    message_pending_ack = 0;
    if (flash_hw_fd >= 0) {
        hw_expansion_set_led_mode(flash_hw_fd, HW_LED_MODE_MANUAL_RGB);
        hw_expansion_set_status_color(flash_hw_fd,
            hw_link_connected ? HW_STATUS_CONNECTED : HW_STATUS_DISCONNECTED);
    }
}

/* --- Boot splash + lock-screen banner: shared box-drawing helpers ---
 *
 * Both draw a "+===...===+ / | text | / +===...===+" box, sized to the
 * text and centered, into whichever window is passed in (stdscr for the
 * boot splash, lock_overlay_win for the lock screen). Deliberately plain
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

/* How long show_splash() will wait for a dismissal tap before giving up
 * and proceeding on its own (2026-08-23 - see that function's own
 * comment for why this is bounded, not a genuinely indefinite wait). */
#define SPLASH_MAX_WAIT_MS 30000

/* Shown once, full-screen on stdscr, before the panel layout exists -
 * purely cosmetic and blocking nothing real: this runs before any
 * thread (idle-input, touch, receiver) has started.
 *
 * 2026-08-23 (direct request): now stays on screen until the touchscreen
 * is tapped, rather than a fixed 1.2s display - for visual effect. This
 * temporarily opens its OWN touch fd (touch_open()/touch_close(), not
 * ui_start_touch()'s persistent one, which hasn't started yet at this
 * point in ui_init() - see this file's touch block comment) and polls it
 * directly in a bounded loop. Bounded, not genuinely indefinite: this
 * project has an established "boots and works with zero manual steps"
 * goal (see the touch block comment's own "receiving always works"
 * reasoning applied elsewhere) - an unattended field reboot with nobody
 * there to tap the screen must still eventually proceed on its own,
 * not sit frozen on a splash forever. SPLASH_MAX_WAIT_MS (30s) is
 * generous enough to be a real "walk up and see it, tap to continue"
 * moment without meaningfully delaying a genuinely unattended boot.
 * Falls back to the original fixed 1.2s display outright if no
 * touchscreen is attached at all (touch_open() failing) - same
 * "hardware absence is never fatal" discipline as every other touch-
 * dependent code path in this project. */
static void show_splash(void)
{
    int box_width = 56;
    int col, row;
    const char *subtitle = "[ ENCRYPTED FIELD TERMINAL ]";
    const char *dismiss_hint = "( tap screen to continue )";

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

    if (has_colors()) {
        attron(COLOR_PAIR(CP_SYSTEM));
    }
    {
        int hintlen = (int)strlen(dismiss_hint);
        int hintcol = col + (box_width - hintlen) / 2;
        if (hintcol < 0) {
            hintcol = col;
        }
        mvprintw(row + 6, hintcol, "%s", dismiss_hint);
    }
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_SYSTEM));
    }

    refresh();

    {
        int splash_touch_fd = touch_open();
        if (splash_touch_fd >= 0) {
            int waited_ms = 0;
            for (;;) {
                touch_point pt;
                int rc = touch_read_tap(splash_touch_fd, &pt, 200);
                if (rc == 1) {
                    break; /* tapped - dismiss now */
                }
                if (rc < 0) {
                    break; /* device error/gone mid-wait - don't hang on it */
                }
                waited_ms += 200;
                if (waited_ms >= SPLASH_MAX_WAIT_MS) {
                    break; /* nobody tapped - proceed unattended */
                }
            }
            touch_close(splash_touch_fd);
        } else {
            napms(1200); /* no touchscreen at all - original fixed delay */
        }
    }

    clear();
    refresh();
}

/* Must be called with ui_mutex held. Draws into lock_overlay_win - a
 * separate window covering the exact same screen rectangle as
 * history_win's (pad) viewport (see both windows' declaration comments)
 * - and shows it, rather than drawing into/erasing the pad itself. This
 * is what actually fixes the older, previously-documented-but-deferred
 * bug where locking used to werase() history_win directly, silently
 * discarding the ENTIRE live in-memory scrollback on every lock cycle:
 * with the pad/overlay split, locking never touches history_win's
 * pad at all, so nothing retained there is ever at risk from a lock
 * cycle again - this was the real architecture change that bug always
 * needed, not a targeted patch. */
static void draw_locked_overlay_locked(void)
{
    int win_width = getmaxx(lock_overlay_win);
    int box_width = win_width - 4;
    int col;

    werase(lock_overlay_win);

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

    wattron(lock_overlay_win, COLOR_PAIR(CP_LOCKED));
    ui_draw_hline(lock_overlay_win, 1, col, box_width);
    ui_draw_centered(lock_overlay_win, 2, col, box_width, "L O C K E D");
    ui_draw_hline(lock_overlay_win, 3, col, box_width);
    wattroff(lock_overlay_win, COLOR_PAIR(CP_LOCKED));

    wattron(lock_overlay_win, COLOR_PAIR(CP_SYSTEM));
    mvwprintw(lock_overlay_win, 5, 1,
              "Messages are still being received normally in the "
              "background.\nEnter your PIN below and press Enter to "
              "unlock.\n");
    wattroff(lock_overlay_win, COLOR_PAIR(CP_SYSTEM));

    wrefresh(lock_overlay_win);
}

/* history_win's viewport occupies the same screen rectangle the old
 * derwin() used to (row 2 = status_win + history_border_win's top
 * border edge; col 1 = history_border_win's left border edge - see
 * ui_init()'s STYLING comment for that offset). */
#define HISTORY_VIEWPORT_TOP_ROW 2
#define HISTORY_VIEWPORT_LEFT_COL 1

/* How many physical pad rows a line of `display_width` characters
 * consumes once written to a `window_width`-column-wide window,
 * starting at column 0 - ncurses wraps a wprintw() write at the
 * window's right edge by default, so a single LOGICAL line (one
 * history_total_lines increment - see this file's touch block comment)
 * can occupy MORE than one physical pad row once its length exceeds the
 * window width. Every site that increments history_total_lines must go
 * through this rather than a flat +1, or the count silently drifts out
 * of sync with the pad's real rows.
 *
 * REAL BUG FOUND (2026-08-22): every increment site originally used a
 * flat +1 regardless of length - harmless for short lines, but this
 * project's own session-start hint ("Type a message...") alone is
 * ~240 characters, well over one 98-column row. Found via an
 * out-of-box reset test: bravo's screen had scrolled the quick-help
 * guide off-screen despite having nowhere near a viewport's worth of
 * genuinely separate lines - the undercount made history_total_lines
 * think less content had been written than the pad had actually
 * consumed, throwing off where "live" (the bottom of the viewport)
 * actually was. */
static int wrapped_row_count(int display_width, int window_width)
{
    int rows;
    if (window_width < 1) {
        window_width = 1;
    }
    if (display_width < 1) {
        return 1;
    }
    rows = (display_width + window_width - 1) / window_width;
    return rows < 1 ? 1 : rows;
}

/* Must be called with ui_mutex held, and only while NOT locked (the
 * lock overlay owns the screen instead - see draw_locked_overlay_locked()).
 * This is the pad equivalent of every old direct wrefresh(history_win)
 * call in this file - it is the ONE place that converts
 * history_view_line/history_following into an actual prefresh() call,
 * so every caller (ui_add_history(), the WiFi-list renderer, the
 * scroll-tap gesture, unlock) stays in sync through one shared
 * implementation rather than duplicating this math. */
static void refresh_history_viewport_locked(void)
{
    int viewport_height = LINES - 6;
    int viewport_width = COLS - 2;
    long shift = (history_total_lines > HISTORY_PAD_LINES)
                     ? (history_total_lines - HISTORY_PAD_LINES) : 0;
    long top_line;
    int pad_row;

    if (viewport_height < 1) {
        viewport_height = 1;
    }
    if (viewport_width < 1) {
        viewport_width = 1;
    }

    if (history_following) {
        top_line = (history_total_lines > viewport_height)
                       ? (history_total_lines - viewport_height) : 0;
    } else {
        top_line = history_view_line;
    }
    if (top_line < shift) {
        top_line = shift; /* can't scroll before the oldest line still
            physically retained in the pad - see HISTORY_PAD_LINES */
    }
    history_view_line = top_line;

    pad_row = (int)(top_line - shift);
    if (pad_row < 0) {
        pad_row = 0;
    }

    prefresh(history_win, pad_row, 0,
             HISTORY_VIEWPORT_TOP_ROW, HISTORY_VIEWPORT_LEFT_COL,
             HISTORY_VIEWPORT_TOP_ROW + viewport_height - 1,
             HISTORY_VIEWPORT_LEFT_COL + viewport_width - 1);
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
        if (!history_following) {
            if (has_colors()) {
                wattron(input_win, COLOR_PAIR(CP_ACCENT));
            }
            mvwprintw(input_win, 0, 0,
                      "[SCROLLED - Down arrow to go forward]");
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

/* Must be called with ui_mutex held. Steps the viewport up (older
 * content, direction<0) or down (newer content, direction>0) by half a
 * viewport - shared by the UP/DOWN arrow-key handling in ui_poll_line()'s
 * UI_MODE_NORMAL branch, the only way to navigate scrollback as of the
 * 2026-08-22 rewrite (see this file's touch block comment for why touch
 * is no longer involved in this at all - real touch-hardware reliability
 * problems surfaced during testing, on top of small-screen taps already
 * being a worse fit for "hold still and pick a spot" than dedicated
 * keys). */
static void scroll_history_locked(int direction)
{
    int viewport_height = LINES - 6;
    int step = viewport_height / 2;

    if (step < 1) {
        step = 1;
    }

    if (direction < 0) {
        /* history_view_line already reflects the current live top even
         * while history_following (refresh_history_viewport_locked()
         * keeps it in sync every time it's called - see its own
         * comment), so this is correct as the starting point whether
         * or not a scroll was already in progress. */
        long shift = (history_total_lines > HISTORY_PAD_LINES)
                         ? (history_total_lines - HISTORY_PAD_LINES) : 0;
        long new_top = history_view_line - step;
        if (new_top < shift) {
            new_top = shift;
        }
        history_view_line = new_top;
        history_following = 0;
    } else if (direction > 0 && !history_following) {
        long live_top = (history_total_lines > viewport_height)
                             ? (history_total_lines - viewport_height) : 0;
        history_view_line += step;
        if (history_view_line >= live_top) {
            history_following = 1;
        }
    } else {
        return; /* direction>0 while already following live - nothing to
            do, avoid an unnecessary prefresh() */
    }
    refresh_history_viewport_locked();
    redraw_input_locked(); /* keeps the [SCROLLED] indicator (see
        redraw_input_locked()) in sync with history_following */
}

/* Must be called with ui_mutex held. Writes whatever msglog_load_recent()
 * currently returns directly into history_win's pad, bumping
 * history_total_lines per line - shared by ui_init() (replay what
 * survived a previous boot) and ui_clear_history() (replay what
 * survived a /clear - see msglog_clear_except_saved()). Each line is
 * ALREADY formatted with its own embedded timestamp
 * (msglog_append()'s own "[YYYY-MM-DD HH:MM:SS] who: text"), so this
 * deliberately writes directly into history_win rather than going
 * through ui_add_history() (which would prepend a SECOND, current-time
 * timestamp on top of the log's own historical one - wrong). Does NOT
 * itself call refresh_history_viewport_locked() or draw_locked_overlay_
 * locked() - callers decide how/whether to reveal it, since ui_init()
 * and ui_clear_history() need to do that differently (ui_init() may
 * still be locked; ui_clear_history() never is, see its own comment). */
static void replay_msglog_into_pad_locked(void)
{
    char recent[20][MSGLOG_LINE_MAX];
    int n = msglog_load_recent(recent,
                                 (int)(sizeof(recent) / sizeof(recent[0])));
    if (n > 0) {
        int i;
        int width = getmaxx(history_win);
        wattron(history_win, COLOR_PAIR(CP_SYSTEM));
        wprintw(history_win, "--- previous session history ---\n");
        history_total_lines += wrapped_row_count(
            (int)strlen("--- previous session history ---"), width);
        for (i = 0; i < n; i++) {
            wprintw(history_win, "%s\n", recent[i]);
            history_total_lines += wrapped_row_count(
                (int)strlen(recent[i]), width);
        }
        wprintw(history_win, "--- end of previous history ---\n");
        history_total_lines += wrapped_row_count(
            (int)strlen("--- end of previous history ---"), width);
        wattroff(history_win, COLOR_PAIR(CP_SYSTEM));
    }
}

void ui_show_help(void)
{
    /* Deliberately one ui_add_history() call per line rather than a
     * single call with embedded '\n's: ui_add_history() bumps
     * history_total_lines exactly once per call, and the real-
     * scrollback math (see this file's touch block comment) assumes
     * that 1 call == 1 physical pad row - a multi-line single call
     * would silently break that alignment (see wrapped_row_count()'s
     * own comment for the bug this exact assumption caused once
     * already, for a different call site). */
    static const char *const help_lines[] = {
        "--- Quick help ---",
        "Ctrl+L: lock now, or set a PIN if none is configured yet",
        "Ctrl+W: WiFi setup (scan, select a network, connect)",
        "Up/Down arrows: scroll message history",
        "/send <path>: send a small local file",
        "/save <text>: send a message that survives /clear",
        "/clear: wipe chat history (keeps any /save'd messages)",
        "/destroy CONFIRM: EMERGENCY - irreversibly wipe ALL chat data",
        "                  on BOTH devices, no exceptions",
        "/help: show this guide again",
        "quit or exit: end the session",
    };
    size_t i;
    for (i = 0; i < sizeof(help_lines) / sizeof(help_lines[0]); i++) {
        ui_add_history(NULL, help_lines[i]);
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

    /* Color setup - see this file's STYLING block comment for the
     * palette rationale. has_colors() is checked defensively - a
     * terminal without color support (shouldn't happen with TERM=linux
     * on the real target, but conceivable elsewhere) just runs
     * monochrome rather than crashing or looking broken.
     *
     * CP_OWN_MSG/CP_PEER_MSG (2026-08-22): changed from cyan/white (too
     * close to each other, and to CP_BORDER/CP_INPUT's own cyan, at a
     * glance) to green/yellow specifically so "who said this" is
     * readable from the color alone, not just the "you:"/"<peer>: "
     * text prefix - a real, direct request after the softer "standard
     * terminal" pass made every message line read as roughly the same
     * color. Green for "you" (a common, low-effort-to-parse convention
     * for one's own messages), yellow for the peer - both stay
     * comfortably distinct from CP_LOCKED's red and CP_SYSTEM's neutral
     * white on the same black background. */
    if (has_colors()) {
        start_color();
        init_pair(CP_STATUS, COLOR_WHITE, COLOR_BLUE);
        init_pair(CP_BORDER, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_PEER_MSG, COLOR_YELLOW, COLOR_BLACK);
        init_pair(CP_OWN_MSG, COLOR_GREEN, COLOR_BLACK);
        init_pair(CP_SYSTEM, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_LOCKED, COLOR_RED, COLOR_BLACK);
        init_pair(CP_INPUT, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_BANNER, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_ACCENT, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_TIMESTAMP, COLOR_BLUE, COLOR_BLACK);
        init_pair(CP_ERROR, COLOR_RED, COLOR_BLACK);
    }

    /* Boot splash - see its own comment above for why this is safe to
     * run here (before any thread starts, before the panel windows
     * exist). Runs once per process start, i.e. once per boot given
     * this app's systemd unit (Restart=always) restarts the whole
     * process on any exit, not just this function. */
    show_splash();

    /* Layout: a 1-row status bar with a filled background (a "title
     * bar" look, via wbkgd() below) plus two bordered panels. Each
     * bordered panel is an OUTER window (box() only). history_border_win's
     * interior is filled by a PAD (history_win - see its declaration
     * comment for why, as of the 2026-08-22 real-scrollback rewrite) shown
     * via prefresh() instead of an inner derwin(); input_border_win still
     * uses the original inner-derwin() pattern (an input line has nothing
     * to scroll back through). lock_overlay_win is a separate plain
     * window sized/positioned to exactly cover history_win's viewport
     * rectangle, shown instead of it while locked. */
    status_win = newwin(1, COLS, 0, 0);

    history_border_win = newwin(LINES - 4, COLS, 1, 0);
    history_win = newpad(HISTORY_PAD_LINES, COLS - 2);
    lock_overlay_win = newwin(LINES - 6, COLS - 2, HISTORY_VIEWPORT_TOP_ROW,
                               HISTORY_VIEWPORT_LEFT_COL);

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
    replay_msglog_into_pad_locked();
    if (ui_mode == UI_MODE_LOCKED) {
        draw_locked_overlay_locked();
    } else {
        refresh_history_viewport_locked();
    }
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);

    ui_set_statusf("Connecting to %s...", peer_label ? peer_label : "?");

    /* Quick help guide - shown once per process start, i.e. once per
     * boot given this app's systemd unit (Restart=always - see
     * show_splash()'s comment for the same reasoning applied there).
     * Factored into ui_show_help() (below) so session.c's "/help"
     * command can print the identical content on demand - 2026-08-22:
     * previously session.c ALSO re-printed a similar instructional line
     * on every single connect/reconnect, which was pure repeated noise
     * for anyone leaving the app running through a flaky link; that's
     * gone now, replaced by "shown once at boot, or whenever you ask". */
    ui_show_help();

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

/* Shared by ui_add_history() (is_error=0) and ui_add_error() (is_error=1,
 * prefix always NULL in practice - see ui_add_error()'s own comment) -
 * the two only ever differ in which color the message BODY gets
 * (CP_SYSTEM vs CP_ERROR); everything else (timestamp handling, pad
 * bookkeeping, lock/scroll gating) is identical, so this is the one
 * place that logic lives rather than two near-duplicate copies. */
static void ui_add_history_ex(const char *prefix, const char *text,
                                int is_error)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    {
        /* Color by source: NULL prefix is a system/event notice (or an
         * error, if is_error - see this function's own comment); "you"
         * (session.c's own convention for the local user's sent
         * messages) gets a distinct color from an incoming peer message
         * (any other non-NULL prefix, i.e. the peer_label session.c
         * passes) - makes it possible to tell at a glance who said what
         * without reading every line. */
        int cp = is_error ? CP_ERROR : CP_SYSTEM;
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
        /* Timestamp itself always in its own quiet CP_TIMESTAMP color
         * (2026-08-22 - previously shared CP_SYSTEM, split out per direct
         * request so timestamps read as visually distinct metadata,
         * regardless of the line's own source/error color. Local
         * wall-clock time only (this device's own clock at receive/send
         * time) - deliberately NOT a value carried on the wire (see
         * PROTOCOL.md's PONG entry for the same reasoning applied to
         * RTT): two devices' clocks aren't guaranteed synchronized
         * (Raspberry Pis have no hardware RTC - see Field WiFi and
         * Network Resilience Concepts.md), so a wire-carried timestamp
         * could be actively misleading across devices in a way a
         * purely local one never is. */
        wattron(history_win, COLOR_PAIR(CP_TIMESTAMP));
        wprintw(history_win, "%s", ts_buf);
        wattroff(history_win, COLOR_PAIR(CP_TIMESTAMP));

        wattron(history_win, COLOR_PAIR(cp));
        if (prefix != NULL) {
            wprintw(history_win, "%s: %s\n", prefix, text != NULL ? text : "");
        } else {
            wprintw(history_win, "%s\n", text != NULL ? text : "");
        }
        wattroff(history_win, COLOR_PAIR(cp));

        /* See wrapped_row_count()'s comment - this line's TOTAL display
         * width (timestamp + optional "prefix: " + text) is what
         * actually determines how many physical pad rows it consumed,
         * not a flat 1. */
        {
            size_t total_width = strlen(ts_buf) +
                (prefix != NULL ? strlen(prefix) + 2 : 0) +
                strlen(text != NULL ? text : "");
            history_total_lines += wrapped_row_count(
                (int)total_width, getmaxx(history_win));
        }
    }
    /* Always write into history_win's pad (above), regardless of lock
     * or scroll state - see this file's lock-screen block comment's
     * DECOUPLING note: the receiver thread calling this must never
     * behave differently based on UI state; the pad genuinely retains
     * it either way (see history_win's declaration comment - this is
     * what actually changed in the 2026-08-22 real-scrollback rewrite).
     * Only the PHYSICAL screen update is gated: while locked, skip it
     * entirely so the lock overlay stays undisturbed on screen until
     * unlock explicitly reveals the pad again - and likewise while
     * history_following is 0 (see this file's touch block comment), so
     * a deliberate "I scrolled back to read this" tap isn't immediately
     * undone by the next incoming message; refresh_history_viewport_locked()
     * itself still tracks history_view_line correctly meanwhile (see its
     * own comment), it just isn't asked to actually paint the screen
     * until the user scrolls back to live or unlocks. */
    if (ui_mode != UI_MODE_LOCKED && history_following) {
        refresh_history_viewport_locked();
    }
    redraw_input_locked();
    pthread_mutex_unlock(&ui_mutex);
}

void ui_add_history(const char *prefix, const char *text)
{
    ui_add_history_ex(prefix, text, 0);
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

/* ui_add_error/ui_add_errorf - same as ui_add_history()/ui_add_historyf(),
 * always with a NULL prefix (an error is a system-level event, never
 * attributed to "you" or the peer - matches how every existing error
 * call site already used NULL), but rendered in CP_ERROR (red) instead
 * of CP_SYSTEM - added 2026-08-22 per direct request to make errors
 * visually distinct from routine status notices, which previously all
 * looked identical. */
void ui_add_error(const char *text)
{
    ui_add_history_ex(NULL, text, 1);
}

void ui_add_errorf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!ui_active) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ui_add_error(buf);
}

/* The "/clear" command's UI-side half (see session.c, which pairs this
 * with msglog_clear_except_saved() - THIS function only touches the
 * live on-screen pad, it never touches the log file itself, so the
 * caller must have already rewritten the file before calling this, or
 * the replay below would just bring the "cleared" content right back).
 * Wipes history_win's pad content outright (unlike locking, which only
 * ever hides the pad behind lock_overlay_win without erasing it - see
 * draw_locked_overlay_locked()'s comment) and resets all scrollback
 * state back to a fresh, empty, live-following pad, then replays
 * whatever's left in the log (i.e. only /save'd lines, once the caller
 * has done its part) so nothing genuinely marked worth keeping
 * disappears from view either. Always leaves history_following=1
 * (there's nothing scrolled-back-to anymore) and never touches lock
 * state - /clear is only ever reachable from an active, unlocked
 * session (see session.c), so there's no lock-overlay interaction to
 * consider here the way ui_init() has to. */
void ui_clear_history(void)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    werase(history_win);
    wmove(history_win, 0, 0);
    history_total_lines = 0;
    history_view_line = 0;
    history_following = 1;
    replay_msglog_into_pad_locked();
    if (ui_mode != UI_MODE_LOCKED) {
        refresh_history_viewport_locked();
    }
    pthread_mutex_unlock(&ui_mutex);
}

/* The "/destroy CONFIRM" emergency-wipe command's UI-side half (see
 * session.c's perform_local_destroy(), which pairs this with
 * msglog_destroy_all() - same DECOUPLING as ui_clear_history() above:
 * this only touches the live on-screen pad). Deliberately does NOT
 * call replay_msglog_into_pad_locked() the way ui_clear_history() does
 * - there is nothing left to replay (msglog_destroy_all() removes the
 * log file entirely, no SAVED exception), and a /destroy is meant to
 * leave a genuinely blank slate, not a "here's what survived" list.
 * The caller is expected to show its own stark confirmation notice via
 * ui_add_error() right after this returns - kept as a separate step
 * rather than built into this function, since the exact wording
 * differs between "you triggered this locally" and "the peer
 * triggered this remotely" (see session.c's two call sites). */
void ui_destroy_history(void)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    werase(history_win);
    wmove(history_win, 0, 0);
    history_total_lines = 0;
    history_view_line = 0;
    history_following = 1;
    if (ui_mode != UI_MODE_LOCKED) {
        refresh_history_viewport_locked();
    }
    pthread_mutex_unlock(&ui_mutex);
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

        /* A real keystroke happened - counts as "the device was used"
         * for the message-pending LED flash, same as a touch tap (see
         * clear_message_pending_flash()'s own comment for why both
         * count, independent of each other's hardware health). Done
         * unconditionally here (before the mode/key dispatch below)
         * rather than duplicated in every branch that could be reached. */
        clear_message_pending_flash();

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
                } else if (ch == KEY_UP) {
                    /* Scrollback navigation (2026-08-22) - see
                     * scroll_history_locked()'s own comment for why
                     * this replaced an earlier touch-tap gesture
                     * entirely, rather than existing alongside it. */
                    scroll_history_locked(-1);
                } else if (ch == KEY_DOWN) {
                    scroll_history_locked(1);
                }
                /* Any other key (function keys, resize, etc.): ignored -
                 * out of scope for this project's UI, see ui.h's touch/
                 * keyboard scope note for the same kind of deliberate,
                 * documented limit. */
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
                        /* Reveal history_win's pad: its screen region was
                         * showing lock_overlay_win the whole time locked
                         * (see draw_locked_overlay_locked()), so
                         * touchwin() is needed to force a full redraw -
                         * ncurses' normal diff-based refresh could
                         * otherwise miss content that changed while this
                         * window wasn't the one being refreshed. Whatever
                         * scroll position the user had before locking
                         * (history_view_line/history_following) is left
                         * exactly as it was - locking never altered it. */
                        touchwin(history_win);
                        refresh_history_viewport_locked();
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
                    /* Remember exactly which ABSOLUTE line (see
                     * history_total_lines' declaration comment) the list
                     * gets drawn at, so a touch tap can be mapped back to
                     * a specific entry - see wifi_list_header_row's own
                     * declaration comment. Forcing history_following=1
                     * here (regardless of any prior scroll state) and
                     * refreshing right after means the just-drawn list is
                     * what the viewport is actually showing when the
                     * user taps it - including staying correct if an
                     * incoming chat message arrives and nudges the live
                     * view up a line while the list is still showing,
                     * since handle_tap_locked()'s WIFI_SELECT branch
                     * reads history_view_line at TAP time, not a cached
                     * value from when the list was drawn. */
                    {
                        int wifi_width = getmaxx(history_win);
                        const char *header_text =
                            "WiFi networks found (Ctrl+W to cancel):";
                        wifi_list_header_row = history_total_lines;
                        wprintw(history_win, "%s\n", header_text);
                        history_total_lines += wrapped_row_count(
                            (int)strlen(header_text), wifi_width);
                        for (i = 0; i < wifi_scan_count; i++) {
                            char entry[128];
                            snprintf(entry, sizeof(entry), "  %d) %s%s",
                                     i + 1, wifi_scan_results[i].ssid,
                                     wifi_scan_results[i].secured
                                         ? " (secured)" : " (open)");
                            wprintw(history_win, "%s\n", entry);
                            history_total_lines += wrapped_row_count(
                                (int)strlen(entry), wifi_width);
                        }
                    }
                    history_following = 1;
                    refresh_history_viewport_locked();
                    ui_mode = UI_MODE_WIFI_SELECT;
                    input_len = 0;
                    input_buf[0] = '\0';
                } else {
                    ui_mode = UI_MODE_NORMAL;
                }
                redraw_input_locked();
                pthread_mutex_unlock(&ui_mutex);

                if (wifi_scan_count <= 0) {
                    ui_add_error(
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
                    ui_add_errorf(
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
            /* "/clear" works here too, not just inside an active
             * session (see session.c's own "/clear" handling and its
             * comment) - a security-motivated "wipe my chat" command
             * shouldn't have to wait for a connection to exist. */
            if (strcmp(dummy, "/clear") == 0) {
                msglog_clear_except_saved();
                ui_clear_history();
                ui_add_history(NULL,
                    "(chat cleared - any /save'd messages were kept)");
            } else if (strcmp(dummy, "/help") == 0) {
                /* Same reasoning as "/clear" just above - purely local,
                 * no connection needed. */
                ui_show_help();
            } else if (strcmp(dummy, "/destroy") == 0) {
                ui_add_error(
                    "EMERGENCY DESTROY: type '/destroy CONFIRM' (exact, "
                    "case-sensitive) to IRREVERSIBLY wipe ALL chat "
                    "history, saved messages, and received files on "
                    "BOTH this device and the paired device. This "
                    "cannot be undone.");
            } else if (strcmp(dummy, "/destroy CONFIRM") == 0) {
                /* Same emergency-wipe protocol as session.c's connected-
                 * path handler - see session.h's session_perform_local_
                 * destroy() comment. No live session exists here by
                 * definition (this is the IDLE thread), so the peer
                 * notification always queues rather than ever attempting
                 * a direct send. */
                session_perform_local_destroy();
                if (outbox_enqueue(OUTBOX_DESTROY_SENTINEL) == 0) {
                    ui_add_error(
                        "EMERGENCY DESTROY: all local chat data wiped. "
                        "Peer notification queued - will be delivered "
                        "automatically once connected.");
                } else {
                    /* Queue is full of unrelated pending messages - this
                     * should be exceedingly rare (OUTBOX_MAX_MESSAGES is
                     * generous), but the wipe command itself must never
                     * silently fail to queue, so this is loud and
                     * explicit about needing a manual retry rather than
                     * pretending success. */
                    ui_add_error(
                        "EMERGENCY DESTROY: all local chat data wiped, "
                        "but the outbound queue is full - peer "
                        "notification could NOT be queued. Run "
                        "'/destroy CONFIRM' again once connected to "
                        "notify the peer.");
                }
            } else if (strncmp(dummy, "/save ", 6) == 0) {
                /* "/save" sends AND tags in one step (see session.c) -
                 * there's no session to send through here, so rather
                 * than silently queuing the raw "/save <text>" string
                 * as if it were a literal chat message (it would be
                 * sent verbatim, "/save" and all, once a session
                 * starts - wrong), say so plainly instead. */
                ui_add_history(NULL,
                    "(/save requires an active connection - not queued)");
            } else {
                /* Something was typed and Enter pressed, but there's no
                 * active session to send it through - queue it (see
                 * outbox.h) rather than silently dropping it, so it goes
                 * out automatically the moment a session actually starts
                 * (session.c drains the outbox right after connecting). */
                if (outbox_enqueue(dummy) == 0) {
                    ui_add_history(NULL, "(not connected - message "
                                          "queued, will send once "
                                          "connected)");
                } else {
                    ui_add_error("(not connected - queue is "
                                  "full, message NOT sent)");
                }
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
        /* history_win's viewport starts at absolute screen row
         * HISTORY_VIEWPORT_TOP_ROW (2) - see that #define. Converting a
         * screen row to an ABSOLUTE line index (matching
         * wifi_list_header_row's own numbering - see its declaration
         * comment) needs history_view_line added back in, unlike the
         * pre-pad version of this code: the viewport no longer always
         * starts at the very first line ever written. */
        long absolute_line = history_view_line +
                              (tap_row - HISTORY_VIEWPORT_TOP_ROW);
        long idx = absolute_line - (wifi_list_header_row + 1);

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
    }
    /* UI_MODE_NORMAL: no touch gesture (as of the 2026-08-22 rewrite -
     * scrollback navigation moved to UP/DOWN arrow keys instead, see
     * scroll_history_locked() and this file's touch block comment for
     * why). Other modes (WIFI_SCANNING, WIFI_PASSWORD, WIFI_CONNECTING,
     * SET_PIN_NEW, SET_PIN_CONFIRM): still no touch gesture defined - a
     * tap during any of these is simply ignored rather than guessed at. */
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
         * rc==1/rc<0 handling below. Alternates between the connection-
         * aware alert color (blue if hw_link_connected, orange if not)
         * and the matching BASE connection color (green/red) - NEVER
         * LED-off, so the link's up/down state stays visible throughout
         * the flash too, not just during the "on" phase - see ui.h's
         * ui_notify_message_pending()/ui_set_link_state() comments for
         * the full 2026-08-22 redesign reasoning, and
         * clear_message_pending_flash() for why a real tap restores the
         * matching base color specifically, not a hardcoded one. */
        if (message_pending_ack && flash_hw_fd >= 0) {
            flash_toggle_counter++;
            if (flash_toggle_counter >= UI_FLASH_TOGGLE_ITERS) {
                flash_toggle_counter = 0;
                flash_led_on = !flash_led_on;
                if (flash_led_on) {
                    hw_expansion_set_status_color(flash_hw_fd,
                        hw_link_connected ? HW_STATUS_MSG_CONNECTED
                                           : HW_STATUS_MSG_DISCONNECTED);
                } else {
                    hw_expansion_set_status_color(flash_hw_fd,
                        hw_link_connected ? HW_STATUS_CONNECTED
                                           : HW_STATUS_DISCONNECTED);
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
             * tap on the message itself - see ui.h's comment and
             * clear_message_pending_flash()'s own. Resetting this
             * thread's own local toggle-animation bookkeeping too
             * (harmless either way, since clear_message_pending_flash()
             * already stops the toggle loop from re-entering on the next
             * iteration by clearing message_pending_ack itself). */
            flash_toggle_counter = 0;
            flash_led_on = 0;
            clear_message_pending_flash();
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
    /* Deliberate honest limit: the flash TOGGLE itself is entirely
     * driven by the touch thread's poll loop (see touch_thread_main
     * above), so if no touchscreen is attached at all (touch_open()
     * failed in ui_start_touch(), touch_thread_running stays 0), a
     * flash could be requested here but would never actually alternate
     * colors. Acknowledgment, however, no longer depends on touch at
     * all - see clear_message_pending_flash(), called from both the
     * touch thread AND ui_poll_line() (any real keystroke) as of the
     * 2026-08-22 rewrite - so a keyboard-only device (or one with a
     * genuinely faulty touchscreen - see this file's touch block
     * comment) can still dismiss the flash even though it would never
     * have visibly toggled colors in the first place without touch. Not
     * worth a separate fallback thread just to also make the toggle
     * itself keyboard-driven - this project's actual deployed hardware
     * always has the touchscreen attached, this is about acknowledgment
     * robustness, not the visual effect. */
    flash_hw_fd = hw_fd;
    message_pending_ack = 1;
}

void ui_set_link_state(int connected)
{
    hw_link_connected = connected ? 1 : 0;
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

void ui_show_help(void)
{
    /* Same quick help guide as the real ncurses build - see that copy's
     * comment for the content itself; kept in sync by hand since the two
     * ui_init()s share no code (see this block's top comment on why this
     * whole fallback exists separately). Callable both from ui_init()
     * below and from session.c's "/help" command. */
    printf("--- Quick help ---\n"
           "Up/Down arrows: scroll message history\n"
           "/send <path>: send a small local file\n"
           "/save <text>: send a message that survives /clear\n"
           "/clear: wipe chat history (keeps any /save'd messages)\n"
           "/destroy CONFIRM: EMERGENCY - irreversibly wipe ALL chat "
           "data on BOTH devices, no exceptions\n"
           "/help: show this guide again\n"
           "quit or exit: end the session\n"
           "(lock screen / WiFi setup are Linux+ncurses-only features,\n"
           " not available in this plain-console fallback)\n");
    fflush(stdout);
}

void ui_init(const char *peer_label)
{
    snprintf(fallback_peer_label, sizeof(fallback_peer_label), "%s",
             peer_label != NULL ? peer_label : "?");
    fallback_prompt_shown = 0;
    ui_show_help();
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

/* No color to distinguish an error with on this plain-console fallback -
 * a textual "ERROR: " prefix is the honest substitute. */
void ui_add_error(const char *text)
{
    printf("\nERROR: %s\n", text != NULL ? text : "");
    fallback_prompt_shown = 0;
    fflush(stdout);
}

void ui_add_errorf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ui_add_error(buf);
}

void ui_clear_history(void)
{
    /* Nothing to clear on-screen here - this fallback is a plain,
     * non-scrolling console (see this block's top comment), it never
     * kept any of its own history buffer the way ncurses' pad does.
     * session.c's msglog_clear_except_saved() call still runs and does
     * the real (on-disk) work regardless of this being a no-op. */
    printf("(chat log cleared - any /save'd messages were kept)\n");
    fflush(stdout);
}

void ui_destroy_history(void)
{
    /* Same reasoning as ui_clear_history() above - nothing to wipe
     * on-screen on this fallback. msglog_destroy_all() still does the
     * real (on-disk) work. */
    printf("(EMERGENCY DESTROY: all local chat data wiped)\n");
    fflush(stdout);
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

void ui_set_link_state(int connected)
{
    (void)connected;
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

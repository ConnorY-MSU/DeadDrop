#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "ui.h"

/* Two implementations selected at compile time: __linux__ (real ncurses) and a plain-stdio fallback elsewhere. See ui.h. */

#ifdef __linux__

#include <ncurses.h>
#include <pthread.h>
#include <unistd.h> /* usleep() - see ui_poll_line()'s comment */
#include <time.h>

#include "lock.h"
#include "wifi.h"
#include "wardrive.h"
#include "touch.h"
#include "hw_expansion.h"
#include "hw_oled.h"
#include "msglog.h"
#include "outbox.h"
/* Only for session_perform_local_destroy() ("/destroy"'s offline case) - narrow exception to not depending on session.h. */
#include "session.h"

/* --- Module state --- */
/* ui_mutex serializes all ncurses calls (not thread-safe). See COMMENT_ARCHIVE.md for a real starvation bug this fixed. */
static WINDOW *status_win = NULL;
static WINDOW *history_border_win = NULL; /* outer window, box() only */
static WINDOW *history_win = NULL;        /* a PAD (newpad()) - retained scrollback, shown via refresh_history_viewport_locked() */
static WINDOW *lock_overlay_win = NULL;   /* shown INSTEAD OF prefresh()-ing history_win's pad while locked */
static WINDOW *input_border_win = NULL;   /* outer window, box() only */
static WINDOW *input_win = NULL;          /* derwin() inside the above */
static pthread_mutex_t ui_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ui_active = 0;

/* This device's own identity, inferred once in ui_init() from peer_label ("not the peer" = self). 1 = Alpha, 0 = Bravo. */
static int g_self_is_alpha = 1;

/* --- Styling --- */
/* Low-bold 8-color/64-pair palette, plain ACS box-drawing only. See COMMENT_ARCHIVE.md. */
#define CP_STATUS   1 /* status "title bar": RED on alpha, BLUE on bravo (white text), set in ui_init() from g_self_is_alpha */
#define CP_BORDER   2 /* panel borders: cyan on black */
/* Pair IDs 3 and 4 retired (message coloring now uses CP_NODE_ALPHA/BRAVO by sender name) - left as a gap. */
#define CP_SYSTEM   5 /* system/event notices: white on black - visually quieter than a real message */
#define CP_LOCKED   6 /* lock screen / danger state: red on black */
#define CP_INPUT    7 /* compose prompt: cyan on black */
#define CP_BANNER   8 /* splash/lock banner box: white on black */
#define CP_ACCENT   9 /* secondary accents (splash subtitle, WiFi transient states): cyan on black */
#define CP_TIMESTAMP 10 /* "[HH:MM:SS] " prefix: yellow on black, split from CP_SYSTEM to avoid clashing with CP_NODE_BRAVO's blue */
#define CP_ERROR    11 /* errors/failures (ui_add_error/errorf): magenta on black, avoids colliding with CP_NODE_ALPHA's red */
#define CP_NODE_ALPHA 12 /* Alpha's identity color: red on black - used wherever the name "Alpha" appears */
#define CP_NODE_BRAVO 13 /* Bravo's identity color: blue on black - used wherever the name "Bravo" appears */

/* Smaller than DD_MAX_BODY_LEN (message.h's 64 KiB cap) - bounds one typed keyboard line; keeps ui.c decoupled from message.h. */
#define UI_INPUT_MAX 2048
static char input_buf[UI_INPUT_MAX];
static size_t input_len = 0;

/* --- Lock screen --- */
/* Ctrl+L locks (or starts PIN setup if none yet); auto-locks after UI_INACTIVITY_TIMEOUT_SECONDS idle. Touches only ncurses/lock.c. */
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

/* General masked-entry buffer: shared by lock-PIN entry/setup and WiFi password entry - never both at once (ui_mode is mutually exclusive). */
static char pin_entry_buf[LOCK_PIN_MAX_LEN + 1];
static size_t pin_entry_len = 0;
static char pin_first_entry_buf[LOCK_PIN_MAX_LEN + 1]; /* holds the first of two entries during UI_MODE_SET_PIN_NEW -> _CONFIRM */
static size_t pin_first_entry_len = 0;

static int wrong_attempt_count = 0;
static time_t next_allowed_check_time = 0;

#define UI_INACTIVITY_TIMEOUT_SECONDS 120
static time_t last_activity_time = 0;

/* --- WiFi setup screen --- */
/* Ctrl+W enters/cancels; wifi_scan()/wifi_connect() are slow subprocess calls, so ui_poll_line() runs them only after releasing ui_mutex. */
static wifi_network wifi_scan_results[WIFI_SCAN_MAX_RESULTS];
static int wifi_scan_count = 0;
static char wifi_selected_ssid[WIFI_SSID_MAX];
static int wifi_selected_secured = 0;
static char wifi_pending_password[LOCK_PIN_MAX_LEN + 1]; /* copied out of pin_entry_buf right before ui_mutex is released, for the deferred connect call */
static long wifi_list_header_row = -1; /* ABSOLUTE line index where the "WiFi networks found" header was drawn; entry i is at +1+i, used to map a tap to a network */

typedef enum {
    UI_PENDING_NONE,
    UI_PENDING_WIFI_SCAN,
    UI_PENDING_WIFI_CONNECT
} ui_pending_action;

/* --- Touch --- */
/* Keyboards remain the only way to TYPE. Touch only handles LOCKED-dismiss and WIFI_SELECT taps; UI_MODE_NORMAL has no gesture (scrolling moved to arrow keys, see COMMENT_ARCHIVE.md). Runs whole process lifetime, no session bracketing needed. */
static int touch_fd = -1;
static pthread_t touch_thread;
static volatile int touch_thread_running = 0;
static volatile int touch_thread_should_stop = 0;

/* --- Real scrollback state (history_win is a PAD) --- */
/* history_total_lines is a stable ever-increasing count (unlike a raw pad row); history_view_line is the viewport's top; history_following==1 pins it live. */
#define HISTORY_PAD_LINES 3000
static long history_total_lines = 0;
static long history_view_line = 0;
static int history_following = 1;

/* --- Message-pending LED flash + OLED background metrics --- */
/* Both piggy-back on the touch thread's existing ~200ms poll loop rather than adding dedicated threads - see ui.h. */
static volatile int message_pending_ack = 0;
static int flash_hw_fd = -1;      /* set per-call by ui_notify_message_pending() */
static int metrics_oled_fd = -1;  /* set once by ui_set_oled_fd() */
static volatile int hw_link_connected = 0; /* kept in sync by ui_set_link_state(); starts 0 since ui_init() runs before any connection attempt */

/* Toggle the flash roughly every 400ms (2 x the ~200ms loop period) - deliberate flash, not a malfunction. */
#define UI_FLASH_TOGGLE_ITERS 2

/* Refresh OLED metrics roughly every 30s (150 x ~200ms) - each refresh is a real nmcli subprocess spawn (see wifi.c), not free. */
#define UI_METRICS_REFRESH_ITERS 150

/* Clears message_pending_ack, shared by touch_thread_main() and ui_poll_line() - callable from either thread without ui_mutex (fd calls are thread-safe). */
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

/* --- Boot splash + lock-screen banner: shared box-drawing helpers --- */
/* Both draw a centered "+===+ / | text | / +===+" box in plain ASCII (see STYLING), sized to the window/text at draw time. */
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
    /* Cap the padding so the box still looks like a box on a narrow terminal. */
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

/* How long show_splash() waits for a dismissal tap before proceeding unattended (bounded, not indefinite). */
#define SPLASH_MAX_WAIT_MS 30000

/* Shared tail for every show_splash() layout: wait for a dismissal tap (own temp touch fd) or a fixed 1.2s delay, then clear the screen. */
static void splash_wait_for_dismiss_and_clear(void)
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

    clear();
    refresh();
}

/* Original single-box splash, kept as the fallback for any console narrower than TWIN_BLOCK_WIDTH needs. */
static void show_splash_simple(void)
{
    int box_width = 56;
    int col, row;
    const char *subtitle = "[ ENCRYPTED FIELD TERMINAL ]";
    const char *dismiss_hint = "( tap screen to continue )";

    if (box_width > COLS - 2) {
        box_width = COLS - 2;
    }
    if (box_width < 10) {
        return; /* pathologically narrow terminal - skip rather than risk garbled output */
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
    ui_draw_centered(stdscr, row + 1, col, box_width, "D E A D D R O P");
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
    splash_wait_for_dismiss_and_clear();
}

/* "Twin Nodes" banner width, fixed (pre-built strings, not reflowable): TWIN_NODE_BOX_WIDTH=14 chars, TWIN_CONNECTOR_WIDTH=34 chars, both verified exactly. */
#define TWIN_NODE_BOX_WIDTH 14
#define TWIN_CONNECTOR_WIDTH 34
#define TWIN_BLOCK_WIDTH (TWIN_NODE_BOX_WIDTH * 2 + TWIN_CONNECTOR_WIDTH)

static void show_splash(void)
{
    /* "Twin Nodes" design: paired devices shown linked in distinct colors; falls back to show_splash_simple() on a narrower console. See COMMENT_ARCHIVE.md. */
    int col, row;
    const char *alpha_box_border = "+------------+";
    const char *alpha_box_mid    = "|   ALPHA    |";
    const char *connector        = "========== L I N K E D ===========";
    const char *bravo_box_border = "+------------+";
    const char *bravo_box_mid    = "|   BRAVO    |";
    const char *title            = "D E A D D R O P";
    const char *subtitle         = "[ ENCRYPTED FIELD TERMINAL ]";
    const char *dismiss_hint     = "( tap screen to continue )";
    int bravo_col;

    if (COLS - 2 < TWIN_BLOCK_WIDTH) {
        show_splash_simple();
        return;
    }

    col = (COLS - TWIN_BLOCK_WIDTH) / 2;
    bravo_col = col + TWIN_NODE_BOX_WIDTH + TWIN_CONNECTOR_WIDTH;
    /* 12 rows tall (box x3 + title + subtitle + hint, with blank rows) - centered like the old 7-row layout, scaled for the new height. */
    row = LINES / 2 - 6;
    if (row < 0) {
        row = 0;
    }

    clear();

    if (has_colors()) {
        attron(COLOR_PAIR(CP_NODE_ALPHA));
    }
    mvprintw(row, col, "%s", alpha_box_border);
    mvprintw(row + 1, col, "%s", alpha_box_mid);
    mvprintw(row + 2, col, "%s", alpha_box_border);
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_NODE_ALPHA));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_ACCENT));
    }
    mvprintw(row + 1, col + TWIN_NODE_BOX_WIDTH, "%s", connector);
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_ACCENT));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_NODE_BRAVO));
    }
    mvprintw(row, bravo_col, "%s", bravo_box_border);
    mvprintw(row + 1, bravo_col, "%s", bravo_box_mid);
    mvprintw(row + 2, bravo_col, "%s", bravo_box_border);
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_NODE_BRAVO));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_BANNER));
    }
    {
        int len = (int)strlen(title);
        int c = col + (TWIN_BLOCK_WIDTH - len) / 2;
        if (c < col) {
            c = col;
        }
        mvprintw(row + 5, c, "%s", title);
    }
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_BANNER));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_ACCENT));
    }
    {
        int len = (int)strlen(subtitle);
        int c = col + (TWIN_BLOCK_WIDTH - len) / 2;
        if (c < col) {
            c = col;
        }
        mvprintw(row + 8, c, "%s", subtitle);
    }
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_ACCENT));
    }

    if (has_colors()) {
        attron(COLOR_PAIR(CP_SYSTEM));
    }
    {
        int len = (int)strlen(dismiss_hint);
        int c = col + (TWIN_BLOCK_WIDTH - len) / 2;
        if (c < col) {
            c = col;
        }
        mvprintw(row + 11, c, "%s", dismiss_hint);
    }
    if (has_colors()) {
        attroff(COLOR_PAIR(CP_SYSTEM));
    }

    refresh();
    splash_wait_for_dismiss_and_clear();
}

/* Must be called with ui_mutex held. Draws into lock_overlay_win instead of erasing history_win's pad directly - fixes an old scrollback-loss bug, see COMMENT_ARCHIVE.md. */
static void draw_locked_overlay_locked(void)
{
    int win_width = getmaxx(lock_overlay_win);
    int box_width = win_width - 4;
    int col;

    werase(lock_overlay_win);

    if (box_width > 40) {
        box_width = 40; /* a compact banner even on a wide screen, rather than stretching to fill it */
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

/* history_win's viewport rectangle: row 2 = below status_win/border top edge; col 1 = inside history_border_win's left border. */
#define HISTORY_VIEWPORT_TOP_ROW 2
#define HISTORY_VIEWPORT_LEFT_COL 1

/* Physical pad rows a `display_width`-char line occupies in a `window_width`-wide window; every history_total_lines increment must use this, not a flat +1 - see COMMENT_ARCHIVE.md for the bug that broke. */
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

/* Must be called with ui_mutex held, and only while NOT locked. The one place that converts view state into an actual prefresh() call. */
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
        top_line = shift; /* can't scroll before the oldest line still physically retained in the pad - see HISTORY_PAD_LINES */
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

/* Mode-aware input-line redraw. Must be called with ui_mutex held. */
static void redraw_input_locked(void)
{
    size_t i;
    int cp = CP_INPUT; /* overridden below for sensitive-entry modes */
    int apply_uniform_color = 1; /* UI_MODE_NORMAL colors itself inline (two-tone ">> " prompt) and skips the trailing mvwchgat below */

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
        /* Two-tone compose prompt: the ">> " glyph is a distinct color from the typed text (exception to the flat trailing-mvwchgat color). */
        if (has_colors()) {
            wattron(input_win, COLOR_PAIR(CP_INPUT));
        }
        wprintw(input_win, ">> ");
        if (has_colors()) {
            wattroff(input_win, COLOR_PAIR(CP_INPUT));
        }
        /* Multi-line compose: input_buf may contain embedded '\n's, but input_win shows only the segment after the last one; full input_buf is sent on Enter. */
        {
            const char *last_nl = strrchr(input_buf, '\n');
            const char *visible = (last_nl != NULL) ? last_nl + 1 : input_buf;
            wprintw(input_win, "%s", visible);
        }
        break;
    }

    /* Applied to the whole line after drawing rather than per-call; skipped for UI_MODE_NORMAL (two-tone prompt, see above). */
    if (apply_uniform_color) {
        mvwchgat(input_win, 0, 0, -1, A_NORMAL, cp, NULL);
    }
    wrefresh(input_win);
}

/* Must be called with ui_mutex held. Steps the viewport up/down by half a viewport - the only way to navigate scrollback (arrow keys) since touch's scroll gesture was dropped, see COMMENT_ARCHIVE.md. */
static void scroll_history_locked(int direction)
{
    int viewport_height = LINES - 6;
    int step = viewport_height / 2;

    if (step < 1) {
        step = 1;
    }

    if (direction < 0) {
        /* history_view_line already reflects the current live top, so it's correct as the starting point regardless of prior scroll state. */
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
        return; /* direction>0 while already following live - nothing to do, avoid an unnecessary prefresh() */
    }
    refresh_history_viewport_locked();
    redraw_input_locked(); /* keeps the [SCROLLED] indicator in sync with history_following */
}

/* Must be called with ui_mutex held. Writes msglog_load_recent()'s lines directly into history_win's pad (each has its own timestamp, so not via ui_add_history()); shared by ui_init()/ui_clear_history(). Doesn't refresh the pad itself. */
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
    /* One ui_add_history() call per line, not one multi-line call - scrollback math assumes 1 call == 1 pad row (see wrapped_row_count()). */
    static const char *const help_lines[] = {
        "--- Quick help ---",
        "Ctrl+L: lock now, or set a PIN if none is configured yet",
        "Ctrl+W: WiFi setup (scan, select a network, connect)",
        "Up/Down arrows: scroll message history",
        "End a line with \\ then Enter to keep composing a multi-line",
        "  message; plain Enter sends what you've typed",
        "/send <path>: send a small local file",
        "/save <text>: send a message that survives /clear",
        "/clear: wipe chat history (keeps any /save'd messages)",
        "/volume: show current speaker volume",
        "/volume <0-100>: set speaker volume",
        "/wardrive: show wardrive mode status",
        "/wardrive on: auto-connect to the strongest open WiFi network",
        "             when no trusted network is in range (mobile use)",
        "/wardrive off: turn wardrive mode back off",
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
    /* Self is whichever of the two names peer_label is NOT (check is `== 0`, not `!= 0` - a real inverted-color bug, see COMMENT_ARCHIVE.md); NULL defaults to Alpha. */
    g_self_is_alpha = (peer_label == NULL || strcmp(peer_label, "Bravo") == 0);

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);

    /* Safety-net cleanup: an unexpected exit() elsewhere would otherwise leave the terminal raw/noecho. ui_shutdown() is idempotent, so registering both is safe. */
    atexit(ui_shutdown);

    /* Color setup - see STYLING above. has_colors() checked defensively so a terminal without color support just runs monochrome. */
    if (has_colors()) {
        start_color();
        init_pair(CP_STATUS, COLOR_WHITE,
                  g_self_is_alpha ? COLOR_RED : COLOR_BLUE);
        init_pair(CP_BORDER, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_SYSTEM, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_LOCKED, COLOR_RED, COLOR_BLACK);
        init_pair(CP_INPUT, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_BANNER, COLOR_WHITE, COLOR_BLACK);
        init_pair(CP_ACCENT, COLOR_CYAN, COLOR_BLACK);
        init_pair(CP_TIMESTAMP, COLOR_YELLOW, COLOR_BLACK);
        init_pair(CP_ERROR, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(CP_NODE_ALPHA, COLOR_RED, COLOR_BLACK);
        init_pair(CP_NODE_BRAVO, COLOR_BLUE, COLOR_BLACK);
    }

    /* Boot splash - safe here, before any thread starts or panel windows exist; runs once per process start (per boot, given systemd Restart=always). */
    show_splash();

    /* Layout: 1-row status bar + two bordered panels. history_border_win's interior is a PAD shown via prefresh(); lock_overlay_win covers its viewport while locked. */
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
    /* Finding #6 fix: load the persisted wrong-PIN rate-limit deadline instead of always starting at 0, so a restart can't reset the delay. */
    if (lock_get_next_allowed_time(&next_allowed_check_time) != 0) {
        next_allowed_check_time = 0;
    }
    last_activity_time = time(NULL);

    /* Locked by default on boot whenever a PIN has ever been set (non-negotiable per the build log); no PIN configured means starts unlocked. */
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

    /* Quick help guide, shown once per boot; factored into ui_show_help() so session.c's "/help" command can print the same content on demand. */
    ui_show_help();

    if (!pin_configured) {
        ui_add_history(NULL, "No PIN set - press Ctrl+L to set one and "
                              "enable the lock screen.");
    }

    /* Started once here, for the whole process lifetime - no session bracketing needed (see Touch block). No-op if no touchscreen attached. */
    ui_start_touch();
}

void ui_set_status(const char *status_text)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    /* werase() fills with status_win's background attribute (CP_STATUS, set via wbkgd() in ui_init()), giving the row a filled "title bar" look. */
    werase(status_win);
    /* A persistent brand prefix, not just the raw status text - always-on chrome since the status bar is visible in every mode. */
    mvwprintw(status_win, 0, 1, "DEADDROP :: %s",
              status_text != NULL ? status_text : "");
    wrefresh(status_win);
    /* Put the cursor back in the input line, otherwise it visibly jumps to wherever the status bar last wrote. */
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

/* Shared by ui_add_history() (is_error=0) and ui_add_error() (is_error=1); they only differ in the message BODY color. */
/* Maps a display NAME ("Alpha"/"Bravo") to its fixed identity color pair; defaults to CP_SYSTEM for anything else. */
static int color_pair_for_name(const char *name)
{
    if (name == NULL) {
        return CP_SYSTEM;
    }
    if (strcmp(name, "Alpha") == 0) {
        return CP_NODE_ALPHA;
    }
    if (strcmp(name, "Bravo") == 0) {
        return CP_NODE_BRAVO;
    }
    return CP_SYSTEM;
}

static void ui_add_history_ex(const char *prefix, const char *text,
                                int is_error)
{
    if (!ui_active) {
        return;
    }
    pthread_mutex_lock(&ui_mutex);
    {
        /* Color by SENDER's identity, not own-vs-peer; session.c's sentinel "you" is substituted here for this device's real capitalized name. */
        const char *display_prefix = prefix;
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
            if (strcmp(prefix, "you") == 0) {
                display_prefix = g_self_is_alpha ? "Alpha" : "Bravo";
            }
            cp = color_pair_for_name(display_prefix);
        }
        /* Timestamp in its own CP_TIMESTAMP color. Local wall-clock time only, never wire-carried (the two Pis' clocks aren't synchronized). */
        wattron(history_win, COLOR_PAIR(CP_TIMESTAMP));
        wprintw(history_win, "%s", ts_buf);
        wattroff(history_win, COLOR_PAIR(CP_TIMESTAMP));

        wattron(history_win, COLOR_PAIR(cp));
        if (display_prefix != NULL) {
            wprintw(history_win, "%s: %s\n", display_prefix, text != NULL ? text : "");
        } else {
            wprintw(history_win, "%s\n", text != NULL ? text : "");
        }
        wattroff(history_win, COLOR_PAIR(cp));

        /* See wrapped_row_count() - this line's TOTAL display width (timestamp + prefix + text) determines pad rows, not a flat 1. */
        {
            size_t total_width = strlen(ts_buf) +
                (display_prefix != NULL ? strlen(display_prefix) + 2 : 0) +
                strlen(text != NULL ? text : "");
            history_total_lines += wrapped_row_count(
                (int)total_width, getmaxx(history_win));
        }
    }
    /* Always writes into the pad regardless of lock/scroll state; only the PHYSICAL screen update is gated (skipped while locked or scrolled back). */
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

/* Same as ui_add_history()/ui_add_historyf() but with a NULL prefix and CP_ERROR color, so errors are visually distinct from routine notices. */
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

/* "/clear"'s UI-side half - wipes the pad, resets scrollback, replays whatever's left in the log (caller must already have rewritten it). Never touches lock state. */
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

/* "/destroy CONFIRM"'s UI-side half - like ui_clear_history() but does NOT replay the log (msglog_destroy_all() removes it entirely). Caller shows its own confirmation. */
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

/* Each lock hold inside ui_poll_line() is capped at this many ms, regardless of the caller's total timeout - gives the receiver thread frequent uncontended windows. */
#define UI_POLL_SLICE_MS 20

/* Runs a WiFi scan and renders the result (network list or "found nothing" error). MUST be called with ui_mutex NOT held and ui_mode already UI_MODE_WIFI_SCANNING. */
static void perform_wifi_scan_flow(void)
{
    int n = wifi_scan(wifi_scan_results, WIFI_SCAN_MAX_RESULTS);
    wifi_scan_count = (n > 0) ? n : 0;

    pthread_mutex_lock(&ui_mutex);
    if (wifi_scan_count > 0) {
        int i;
        /* Remember the ABSOLUTE line the list is drawn at (wifi_list_header_row) so a touch tap maps back to an entry; force history_following=1 so the list stays visible. */
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
}

ui_poll_result ui_poll_line(char *out_line, size_t out_line_size,
                             int timeout_ms)
{
    int elapsed_ms = 0;

    if (!ui_active) {
        return UI_POLL_TIMEOUT;
    }

    while (elapsed_ms < timeout_ms) {
        int ch;
        const char *pending_history_msg = NULL; /* can't call ui_add_history() while ui_mutex is held, so queue it and add AFTER unlocking this slice */
        ui_pending_action pending_action = UI_PENDING_NONE; /* same idea, for a slow wifi_scan()/wifi_connect() call that must not run while ui_mutex is held */
        int slice_ms = UI_POLL_SLICE_MS;
        if (elapsed_ms + slice_ms > timeout_ms) {
            slice_ms = timeout_ms - elapsed_ms;
        }

        pthread_mutex_lock(&ui_mutex);

        /* Inactivity auto-lock - only relevant when unlocked AND a PIN exists (see Lock screen block). */
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
            /* Nothing typed this slice. Unlock and sleep OUTSIDE the lock so the receiver thread gets an uncontended window every slice. */
            pthread_mutex_unlock(&ui_mutex);
            elapsed_ms += slice_ms;
            usleep(1000);
            continue;
        }

        /* A real keystroke counts as "device used" for the message-pending LED flash, same as a touch tap - done once here. */
        clear_message_pending_flash();

        {
            ui_poll_result result = UI_POLL_TIMEOUT;

            if (ch == 12 && ui_mode == UI_MODE_NORMAL) {
                /* Ctrl+L (ASCII 12): lock screen entry, doubling as PIN setup. Only from UI_MODE_NORMAL, so it can't jump in mid WiFi-setup. */
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
                /* Ctrl+W (ASCII 23): WiFi setup entry, doubling as "cancel" mid-flow. Excludes UI_MODE_LOCKED and PIN-setup modes. */
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
                    /* Trailing-backslash line-continuation for multi-line compose - chosen since a raw Linux console can't reliably detect Shift+Enter. */
                    if (input_len > 0 && input_buf[input_len - 1] == '\\') {
                        input_len--;
                        if (input_len + 1 < sizeof(input_buf)) {
                            input_buf[input_len++] = '\n';
                        }
                        input_buf[input_len] = '\0';
                        redraw_input_locked();
                    } else {
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
                    }
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
                    /* else: silently drop the keystroke once UI_INPUT_MAX is hit - a deliberate cap, not a bug. */
                } else if (ch == KEY_UP) {
                    /* Scrollback navigation - replaced an earlier touch-tap gesture, see scroll_history_locked(). */
                    scroll_history_locked(-1);
                } else if (ch == KEY_DOWN) {
                    scroll_history_locked(1);
                }
                /* Any other key (function keys, resize, etc.): ignored, out of scope for this UI - see ui.h. */
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
                        lock_clear_next_allowed_time(); /* Finding #6 fix - clear the persisted deadline too, not just in-memory, on unlock */
                        last_activity_time = time(NULL);
                        /* Reveal history_win's pad: touchwin() forces a full redraw since ncurses' diff-based refresh could miss changes made while hidden. */
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
                        /* Finding #6 fix: persist the deadline too, best-effort - a write failure just means it won't survive a restart. */
                        lock_set_next_allowed_time(next_allowed_check_time);

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
                /* Reuses input_buf (unmasked) rather than pin_entry_buf - a network list index isn't sensitive; digits only accepted. */
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                    int idx = atoi(input_buf) - 1; /* shown 1-based to the person typing, stored 0-based internally */
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
            /* UI_MODE_WIFI_SCANNING / UI_MODE_WIFI_CONNECTING: transient states, no key handling beyond the Ctrl+W cancel above. */

            pthread_mutex_unlock(&ui_mutex);

            if (pending_history_msg != NULL) {
                ui_add_history(NULL, pending_history_msg);
            }

            if (pending_action == UI_PENDING_WIFI_SCAN) {
                /* Shared with the automatic no-connectivity-at-boot trigger in idle_input_thread_main(). */
                perform_wifi_scan_flow();
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
                /* Zero the password out of memory as soon as it's no longer needed, rather than leaving a stale static copy. */
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
            /* A keystroke that wasn't a submitted line yet - keep polling for the rest of the caller's requested timeout. */
            elapsed_ms += slice_ms;
        }
    }

    return UI_POLL_TIMEOUT;
}

void ui_shutdown(void)
{
    /* Belt-and-suspenders: stop the idle/touch threads before endwin() in case a caller forgot to bracket a session or is exiting abnormally. */
    ui_stop_idle_input();
    ui_stop_touch();
    if (ui_active) {
        ui_active = 0;
        endwin();
    }
}

/* --- Idle input --- */
/* Runs ui_poll_line() on a dedicated thread whenever no session is active, so lock-screen interaction still works while disconnected. See ui.h. */
static pthread_t idle_thread;
static volatile int idle_thread_running = 0;
static volatile int idle_thread_should_stop = 0;

/* How often the idle thread runs wifi_has_connectivity() (a real subprocess spawn, see wifi.c) - only writes the status bar when there's no connectivity. */
#define UI_CONNECTIVITY_CHECK_SECONDS 15

static void *idle_input_thread_main(void *arg)
{
    char dummy[OUTBOX_MSG_MAX_LEN]; /* sized for a real queued message, not just a throwaway buffer - see the UI_POLL_LINE handling below */
    time_t last_connectivity_check = 0;
    (void)arg;

    /* AUTOMATIC WIFI SETUP ON BOOT: if no network path exists when this thread starts, jump straight into WiFi setup - runs exactly ONCE, not in the periodic re-check, so a cancel doesn't get re-triggered 15s later. */
    pthread_mutex_lock(&ui_mutex);
    if (ui_mode == UI_MODE_NORMAL && !wifi_has_connectivity()) {
        ui_mode = UI_MODE_WIFI_SCANNING;
        redraw_input_locked();
        pthread_mutex_unlock(&ui_mutex);
        ui_add_history(NULL,
            "No network detected at boot - starting WiFi setup "
            "automatically (Ctrl+W to cancel).");
        perform_wifi_scan_flow();
        /* Seed the first-iteration check to "just checked" so it doesn't immediately overwrite the status bar right after this returns. */
        last_connectivity_check = time(NULL);
    } else {
        pthread_mutex_unlock(&ui_mutex);
    }

    while (!idle_thread_should_stop) {
        ui_poll_result pr = ui_poll_line(dummy, sizeof(dummy), 200);
        if (pr == UI_POLL_LINE) {
            /* "/clear" works here too, not just inside an active session - a "wipe my chat" command shouldn't need a connection. */
            if (strcmp(dummy, "/clear") == 0) {
                msglog_clear_except_saved();
                ui_clear_history();
                ui_add_history(NULL,
                    "(chat cleared - any /save'd messages were kept)");
            } else if (strcmp(dummy, "/help") == 0) {
                /* Same reasoning as "/clear" above - purely local, no connection needed. */
                ui_show_help();
            } else if (strcmp(dummy, "/wardrive") == 0) {
                /* Same reasoning as "/clear"/"/help" above - a device-level WiFi setting, not a chat command, so it works with no peer connected. wardrive_status_line() runs a subprocess call (nmcli) - safe here, this loop body already runs outside ui_mutex (see ui_poll_line() above). */
                char status[160];
                wardrive_status_line(status, sizeof(status));
                ui_add_history(NULL, status);
            } else if (strcmp(dummy, "/wardrive on") == 0) {
                wardrive_set_enabled(1);
                ui_add_history(NULL,
                    "(wardrive mode: ON - will auto-connect to the "
                    "strongest open network when no trusted network is "
                    "in range)");
            } else if (strcmp(dummy, "/wardrive off") == 0) {
                wardrive_set_enabled(0);
                ui_add_history(NULL, "(wardrive mode: OFF)");
            } else if (strcmp(dummy, "/destroy") == 0) {
                ui_add_error(
                    "EMERGENCY DESTROY: type '/destroy CONFIRM' (exact, "
                    "case-sensitive) to IRREVERSIBLY wipe ALL chat "
                    "history, saved messages, and received files on "
                    "BOTH this device and the paired device. This "
                    "cannot be undone.");
            } else if (strcmp(dummy, "/destroy CONFIRM") == 0) {
                /* Same emergency-wipe protocol as session.c's connected-path handler; no live session here, so notification always queues. */
                session_perform_local_destroy();
                if (outbox_enqueue(OUTBOX_DESTROY_SENTINEL) == 0) {
                    ui_add_error(
                        "EMERGENCY DESTROY: all local chat data wiped. "
                        "Peer notification queued - will be delivered "
                        "automatically once connected.");
                } else {
                    /* Queue is full (rare, OUTBOX_MAX_MESSAGES is generous) - the wipe command must never silently fail to queue. */
                    ui_add_error(
                        "EMERGENCY DESTROY: all local chat data wiped, "
                        "but the outbound queue is full - peer "
                        "notification could NOT be queued. Run "
                        "'/destroy CONFIRM' again once connected to "
                        "notify the peer.");
                }
            } else if (strncmp(dummy, "/save ", 6) == 0) {
                /* "/save" sends AND tags in one step; queuing the raw text would send it verbatim ("/save" and all) once a session starts. */
                ui_add_history(NULL,
                    "(/save requires an active connection - not queued)");
            } else {
                /* No active session - queue it (see outbox.h) rather than dropping it; session.c drains the outbox once one starts. */
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
        /* UI_POLL_TIMEOUT: normal, keep looping. UI_POLL_QUIT: never returned by the real ncurses ui_poll_line() - see ui.h. */

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

/* --- Touch thread --- */
/* See the Touch block above; unlike idle-input, this thread needs no start/stop bracketing around sessions. */

/* Must be called with ui_mutex held. tap_row/tap_col are already screen-relative (0..LINES-1 / 0..COLS-1). */
static void handle_tap_locked(int tap_row, int tap_col)
{
    (void)tap_col; /* every gesture here is row-based - kept for a possible future column-sensitive gesture */

    if (ui_mode == UI_MODE_LOCKED) {
        /* Clears any lingering "Wrong PIN" message and redraws a clean prompt - the analog to "wake/dismiss a screensaver". */
        redraw_input_locked();
    } else if (ui_mode == UI_MODE_WIFI_SELECT) {
        /* Converts a screen row to an ABSOLUTE line index (matching wifi_list_header_row's numbering) by adding history_view_line back in. */
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
            /* Lands on the password prompt even for an open network - this thread has no access to ui_poll_line()'s pending_action mechanism. */
            ui_mode = UI_MODE_WIFI_PASSWORD;
            redraw_input_locked();
        }
    }
    /* UI_MODE_NORMAL: no touch gesture (scrollback moved to arrow keys). Other modes: no gesture defined either - a tap is simply ignored. */
}

/* Draws WiFi SSID/signal/link-rate and connectivity into the OLED framebuffer, below other callers' lines (see hw_oled.h). Does NOT hold ui_mutex - the fd-based API is thread-safe. */
static void refresh_oled_metrics(void)
{
    wifi_link_info info;
    /* Sized to hold the longest formatted string (SSID + prefix), not HW_OLED_COLS+1 - hw_oled_draw_text() already truncates safely. */
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

    /* wifi_has_connectivity() reused here rather than re-implementing an equivalent check (also used by the idle thread's status prompt). */
    hw_oled_draw_text(metrics_oled_fd, 5,
                       wifi_has_connectivity() ? "Net: OK" : "Net: DOWN");

    hw_oled_display(metrics_oled_fd);
}

static void *touch_thread_main(void *arg)
{
    int flash_toggle_counter = 0;
    int flash_led_on = 0;
    int metrics_counter = UI_METRICS_REFRESH_ITERS; /* draw once immediately on the first loop iteration, rather than waiting a full 30s */
    (void)arg;

    while (!touch_thread_should_stop) {
        touch_point pt;
        int rc = touch_read_tap(touch_fd, &pt, 200);

        /* Message-pending flash toggle, runs every iteration regardless of taps - alternates alert/base color, never LED-off. */
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

        /* OLED background metrics refresh - same "every iteration" shape as the flash toggle above, just on a much coarser interval. */
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

            /* ANY tap acknowledges a pending message flash, not just a tap on the message itself. */
            flash_toggle_counter = 0;
            flash_led_on = 0;
            clear_message_pending_flash();
        } else if (rc < 0) {
            /* Device error (e.g. unplugged) - stop trying rather than spin on a broken fd. */
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
    /* The flash TOGGLE needs the touch thread's poll loop, but acknowledgment doesn't - clear_message_pending_flash() also runs on any keystroke. */
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
    /* Written immediately rather than waiting for the ~30s metrics timer - arrives only every SESSION_PING_INTERVAL_SECONDS, no I2C hammering risk. */
    snprintf(line, sizeof(line), "RTT: %dms", rtt_ms);
    hw_oled_draw_text(metrics_oled_fd, 6, line);
    hw_oled_display(metrics_oled_fd);
}

#else /* !__linux__ */

/* --- Non-Linux fallback --- */
/* Plain stdio, replicating what session.c's printf/fgets console handling did before this module existed. */

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/select.h>
#endif

static char fallback_peer_label[32];
static int fallback_prompt_shown = 0;

/* Platform-specific bounded poll: POSIX select() on fd 0; Windows WaitForSingleObject() (a signaled handle doesn't guarantee a full line, accepted imprecision). */
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
    /* Same quick help guide as the real ncurses build, kept in sync by hand since the two ui_init()s share no code. */
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

/* No color on this plain-console fallback - a textual "ERROR: " prefix is the substitute. */
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
    /* Nothing to clear on-screen - this plain console keeps no history buffer; msglog_clear_except_saved() still does the real on-disk work. */
    printf("(chat log cleared - any /save'd messages were kept)\n");
    fflush(stdout);
}

void ui_destroy_history(void)
{
    /* Same reasoning as ui_clear_history() above - nothing to wipe on-screen; msglog_destroy_all() still does the real on-disk work. */
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

/* No lock screen on this fallback (Linux/ncurses-only feature, see ui.h) - no-ops, present only so callers can use these unconditionally. */
void ui_start_idle_input(void)
{
}

void ui_stop_idle_input(void)
{
}

/* No touchscreen on this project's Windows dev machine - see touch.h. No-ops, present only for unconditional cross-platform calls. */
void ui_start_touch(void)
{
}

void ui_stop_touch(void)
{
}

/* No case RGB LEDs or OLED on this project's Windows dev machine - see hw_expansion.h/hw_oled.h. No-ops, present for unconditional calls. */
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

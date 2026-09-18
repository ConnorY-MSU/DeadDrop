#ifndef UI_H
#define UI_H

#include <stddef.h>
#include <stdarg.h>

/* ui - ncurses terminal UI (touchscreen primary, hw_oled.h secondary). Active for the whole process lifetime. No-op/stdio-fallback on non-Linux. See COMMENT_ARCHIVE.md. */

/* ui_init - start the UI; call exactly once, early in main(), before connecting. peer_label is the other device's short name shown in the status bar. */
void ui_init(const char *peer_label);

/* ui_set_status - update the status-bar line (row 0). Thread-safe, callable any time. */
void ui_set_status(const char *status_text);

/* ui_set_statusf - printf-style version of ui_set_status(). */
void ui_set_statusf(const char *fmt, ...);

/* ui_add_history - append one line to the scrolling message/event history window; `prefix` (e.g. "alpha", "you", NULL) is rendered before `text`. Thread-safe. */
void ui_add_history(const char *prefix, const char *text);

/* ui_add_historyf - printf-style version of ui_add_history(). */
void ui_add_historyf(const char *prefix, const char *fmt, ...);

/* ui_add_error/ui_add_errorf - same as ui_add_history()/ui_add_historyf() but rendered in the "error" color. Thread-safe. */
void ui_add_error(const char *text);
void ui_add_errorf(const char *fmt, ...);

/* ui_show_help - prints the quick-help guide into the history. Called once from ui_init() and by the "/help" command. */
void ui_show_help(void);

/* ui_clear_history - the on-screen half of "/clear" (pairs with msglog_clear_except_saved()). Thread-safe. */
void ui_clear_history(void);

/* ui_destroy_history - the on-screen half of "/destroy CONFIRM" (pairs with msglog_destroy_all()); unlike ui_clear_history(), replays nothing back. Thread-safe. */
void ui_destroy_history(void);

typedef enum {
    UI_POLL_TIMEOUT, /* timeout elapsed, no complete line yet - keep polling */
    UI_POLL_LINE,    /* a full line was composed and submitted (Enter) */
    UI_POLL_QUIT     /* stdin closed (EOF) - non-Linux fallback only, see COMMENT_ARCHIVE.md */
} ui_poll_result;

/* ui_poll_line - wait up to timeout_ms for the user to compose and submit one line; out_line/out_line_size filled in only on UI_POLL_LINE. */
ui_poll_result ui_poll_line(char *out_line, size_t out_line_size,
                             int timeout_ms);

/* ui_shutdown - clean up (endwin() on Linux). MUST run on every exit path; safe to call more than once. */
void ui_shutdown(void);

/* ui_start_idle_input/ui_stop_idle_input - lets the lock screen (PIN entry, Ctrl+L) work while no session is active; mutually exclusive with an active session. No-op on non-Linux. See COMMENT_ARCHIVE.md. */
void ui_start_idle_input(void);
void ui_stop_idle_input(void);

/* ui_start_touch/ui_stop_touch - touchscreen "selection + wake" support (lock-screen tap, WiFi selection, history pause/resume); ui_init() already calls this once. No-op on non-Linux or with no touchscreen. See COMMENT_ARCHIVE.md. */
void ui_start_touch(void);
void ui_stop_touch(void);

/* ui_notify_message_pending - flashes the case RGB LEDs for an unread message until acknowledged by any input. No-op on non-Linux or hw_fd<0. See COMMENT_ARCHIVE.md. */
void ui_notify_message_pending(int hw_fd);

/* ui_set_link_state - tells ui.c whether the mTLS session is up (connected != 0) or down, for LED-flash color selection. Safe to call unconditionally. */
void ui_set_link_state(int connected);

/* ui_set_oled_fd - one-time setter so ui.c can periodically refresh a network-metrics section (SSID/signal/link rate) on the OLED; call once, right after hw_oled_open(). fd may be -1. No-op on non-Linux. */
void ui_set_oled_fd(int fd);

/* ui_report_rtt - report a fresh PING/PONG round-trip-time sample (ms) for the OLED metrics section; called by session.c roughly every SESSION_PING_INTERVAL_SECONDS. No-op on non-Linux. */
void ui_report_rtt(int rtt_ms);

#endif /* UI_H */

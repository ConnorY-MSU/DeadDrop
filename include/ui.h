#ifndef UI_H
#define UI_H

#include <stddef.h>
#include <stdarg.h>

/*
 * ui - ncurses terminal UI for the FNK0100's touchscreen (Week 4 Days
 * 2-3). Real design decisions made and documented here, per
 * ncurses UI Concepts.md:
 *
 * - DISPLAY HIERARCHY: this is the PRIMARY display - the 4.3" DSI
 *   touchscreen shows this UI's full status bar, full scrolling message
 *   history, and the actual compose line. The FNK0100's small 128x64
 *   OLED (hw_oled.h) is explicitly SECONDARY: a brief, glanceable
 *   notification surface for when someone isn't right in front of the
 *   touchscreen, never a substitute for it. Concretely, this governs
 *   what belongs where: full text, full history, and real interaction
 *   belong here; short previews and at-a-glance status belong on the
 *   OLED. See hw_oled.h's matching comment.
 * - CONCURRENCY: reuses session.c's existing threaded design rather
 *   than introducing a second, competing concurrency model. session.c
 *   already has a receiver thread (always processing incoming
 *   messages) and a polling sender loop (bounded-timeout input checks
 *   between re-checking connection state) - solved and tested during
 *   the two-way redesign. The UI layer just plugs into that same
 *   shape: the receiver thread calls ui_add_history()/ui_set_status()
 *   instead of printf(), the sender loop calls ui_poll_line() instead
 *   of the old stdin_ready()+fgets() combo. ui_poll_line()'s own
 *   internal use of a short-timeout wgetch() is a mechanical detail of
 *   HOW it implements "wait up to N ms for one submitted line," not a
 *   second concurrency architecture - the walkthrough's "Option 1
 *   non-blocking single loop" was considered and deliberately not
 *   chosen, since it would mean re-deriving the same thread-safety
 *   work already done for wolfSSL (see session.h) with no benefit.
 * - WINDOWS: three separate WINDOW*s (status/history/input), matching
 *   ncurses UI Concepts.md's own given layout - a natural fit since
 *   each region updates at a different rate (status rarely, history on
 *   every message, input every keystroke).
 * - SCOPE: the UI is active for the whole process lifetime (call
 *   ui_init() once, early in main() - client.c's reconnect loop and
 *   server.c's accept loop both call ui_set_status() too, not just
 *   session.c), not just per-connection. A device meant to sit in a
 *   case with its screen always showing something coherent shouldn't
 *   flip between a plain scrolling console and a full-screen UI
 *   depending on connection state.
 * - TOUCH: honest, limited scope, per ncurses UI Concepts.md's own
 *   suggested framing - this is a keyboard-driven UI. The touchscreen
 *   displays the same UI as any other terminal attached to the Pi;
 *   this does not implement an on-screen keyboard for message compose.
 *
 * Platform: real ncurses implementation on Linux. On non-Linux (this
 * project's Windows dev machine), every function below is a no-op or
 * a plain-stdio fallback replicating exactly what client.c/server.c/
 * session.c did before this module existed - see ui.c. This keeps
 * dev-machine testing/behavior unchanged, matching this project's
 * hw_expansion.h/hw_oled.h precedent of "always callable, real
 * implementation on Linux only."
 */

/*
 * ui_init - start the UI. Call exactly once, early in main(), before
 * any connection attempt. On Linux: enters full-screen ncurses mode,
 * creates the three windows, and registers ui_shutdown() as an
 * atexit() safety net (see ui.c for why that's a safety net and not
 * the only cleanup path relied on). On non-Linux: no-op.
 *
 * peer_label: short text describing the OTHER side's role ("server"
 * or "client") - shown in the status bar's static portion.
 */
void ui_init(const char *peer_label);

/*
 * ui_set_status - update the status-bar line (row 0). Safe to call at
 * any time, including before any connection exists ("Connecting..."),
 * between connections ("Disconnected - retrying in 4s..."), and during
 * an active session ("Connected"). Thread-safe.
 */
void ui_set_status(const char *status_text);

/*
 * ui_set_statusf - printf-style version of ui_set_status(). Exists so
 * the many existing fprintf(stderr, "...", args)/printf("...", args)
 * call sites throughout client.c/server.c (connect/handshake/socket
 * errors, retry countdowns, etc.) can convert to the UI with a
 * near-mechanical swap - same format string and arguments, just routed
 * here instead of a raw stream, since ANY stray direct printf/fprintf
 * once the UI is active would corrupt the ncurses-managed screen (see
 * this header's top comment).
 */
void ui_set_statusf(const char *fmt, ...);

/*
 * ui_add_history - append one line to the scrolling message/event
 * history window. `prefix` (e.g. "server", "client", NULL for none) is
 * rendered before `text`. Thread-safe - called from both the main
 * thread (connection-level notices) and session.c's receiver thread
 * (incoming messages); see ui.c for the locking, and its comment on
 * why the lock is never held across a blocking wait.
 */
void ui_add_history(const char *prefix, const char *text);

/* ui_add_historyf - printf-style version of ui_add_history() - see
 * ui_set_statusf()'s comment above for why this exists. */
void ui_add_historyf(const char *prefix, const char *fmt, ...);

typedef enum {
    UI_POLL_TIMEOUT, /* timeout elapsed, no complete line yet - keep polling */
    UI_POLL_LINE,    /* a full line was composed and submitted (Enter) */
    UI_POLL_QUIT     /* stdin closed (EOF) - only ever returned by the
                       * non-Linux plain-stdio fallback, which can detect
                       * this cleanly via fgets(). The real ncurses path
                       * has no equivalent single-call EOF signal
                       * distinct from "nothing typed yet" - typing
                       * "quit"/"exit" (session.c's own, unchanged,
                       * command handling) is the only way to leave an
                       * active ncurses session. Documented honestly as
                       * a real, deliberate scope limit, not silently
                       * glossed over. */
} ui_poll_result;

/*
 * ui_poll_line - wait up to timeout_ms for the user to compose and
 * submit one line of input. Never blocks longer than timeout_ms, so a
 * caller loop (session.c) can keep re-checking other state (like
 * whether the peer has disconnected) between calls.
 *
 * out_line/out_line_size: filled in (NUL-terminated, no trailing
 * newline) only on UI_POLL_LINE.
 */
ui_poll_result ui_poll_line(char *out_line, size_t out_line_size,
                             int timeout_ms);

/*
 * ui_shutdown - clean up (endwin() on Linux, restoring the terminal to
 * normal mode). MUST run on every exit path - a program that skips
 * this leaves the user's terminal visibly broken. Safe to call more
 * than once, and safe even if ui_init() was never called or the UI
 * isn't active.
 */
void ui_shutdown(void);

/*
 * IDLE INPUT - real gap found via live hardware testing of the lock
 * screen (see TESTING.md), fixed here: ui_poll_line() (and therefore
 * ALL lock-screen interaction - Ctrl+L, PIN entry, first-time PIN
 * setup) was only ever called from inside run_symmetric_session()'s
 * sender loop, meaning a person could not interact with the lock
 * screen at all while a device was disconnected/reconnecting -
 * server.c's accept() in particular blocks indefinitely with no input
 * polling while idle.
 *
 * ui_start_idle_input() spawns a dedicated thread that calls
 * ui_poll_line() in a loop, servicing lock-screen keys the same way an
 * active session's sender loop would, whenever no session is active.
 * Any line actually "submitted" while idle (Enter pressed with nothing
 * to send it through) is not sent anywhere - there's no connection -
 * a brief note is added to history explaining that instead of silently
 * dropping typed input.
 *
 * ui_start_idle_input()/ui_stop_idle_input() are temporally mutually
 * exclusive with an active session by construction: the idle thread
 * and run_symmetric_session()'s own sender loop must never both be
 * reading input_win at the same time. It is the CALLER's job
 * (client.c's reconnect loop, server.c's accept loop) to maintain that
 * invariant - call ui_stop_idle_input() immediately before starting a
 * session and ui_start_idle_input() again immediately after it ends.
 *
 * No-ops on non-Linux (the fallback path has no lock screen at all -
 * see ui.c) - safe to call unconditionally from client.c/server.c on
 * either platform.
 */
void ui_start_idle_input(void);
void ui_stop_idle_input(void);

#endif /* UI_H */

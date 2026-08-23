#ifndef OUTBOX_H
#define OUTBOX_H

#include <stddef.h>

/*
 * outbox - a small, bounded, thread-safe FIFO for TEXT_MESSAGEs typed
 * while no session is active (or a send failed mid-session), so they
 * get sent automatically the moment a session starts/resumes instead
 * of being silently dropped. Deliberately a standalone module, not
 * folded into ui.c or session.c: ui.c's idle-input thread is the
 * PRODUCER (a line submitted with nothing to send it through),
 * session.c's sender loop is the CONSUMER (drains it once connected) -
 * this is genuinely shared state between two otherwise-decoupled
 * layers, same reasoning as every other small focused module in this
 * project (lock.c, wifi.c, touch.c).
 *
 * Cross-platform: pure in-memory queue, no OS-specific calls, no
 * __linux__ split needed - unlike hw_expansion.c/wifi.c/touch.c, this
 * is fully testable on the dev machine too.
 */

#define OUTBOX_MAX_MESSAGES 20   /* bounded, not unbounded - see
    outbox_enqueue()'s contract for what happens once full. 20 is
    generous for the actual use case (a person composing faster than
    reconnects happen), not a general store-and-forward mailbox. */
#define OUTBOX_MSG_MAX_LEN 2048  /* matches ui.h's UI_INPUT_MAX - a
    queued message is, by construction, something that was typed
    interactively, never longer than what the compose line itself
    allows */

/*
 * outbox_enqueue - add one message to the back of the queue.
 * Returns 0 on success, -1 if the queue is already full (the message
 * is NOT silently dropped from the caller's perspective - it never
 * entered the queue at all, and the caller is expected to tell the
 * person directly, e.g. via ui_add_history(), rather than this module
 * doing that itself: outbox.c has no knowledge of ui.c, deliberately -
 * see this header's top comment on why these are separate layers).
 */
int outbox_enqueue(const char *text);

/*
 * outbox_try_dequeue - remove and return the oldest queued message, if
 * any. Returns 1 and fills out_text (NUL-terminated) if a message was
 * dequeued, 0 if the queue was empty (out_text left untouched).
 */
int outbox_try_dequeue(char *out_text, size_t out_text_size);

/*
 * outbox_count - how many messages are currently queued. Used only for
 * UI feedback (e.g. "3 queued messages will send once connected");
 * never load-bearing for correctness.
 */
int outbox_count(void);

#endif /* OUTBOX_H */

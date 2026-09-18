#ifndef OUTBOX_H
#define OUTBOX_H

#include <stddef.h>

/* outbox - small, bounded, thread-safe FIFO for messages typed while no session is active; sent automatically once one starts/resumes. */

#define OUTBOX_MAX_MESSAGES 20   /* bounded; 20 is generous for a person composing faster than reconnects happen, not a general mailbox. */
#define OUTBOX_MSG_MAX_LEN 2048  /* matches ui.h's UI_INPUT_MAX, the max length of a typed compose line */

/* outbox_enqueue - add one message to the back of the queue; returns 0 on success, -1 if full. */
int outbox_enqueue(const char *text);

/* outbox_try_dequeue - remove and return the oldest queued message; returns 1 and fills out_text if dequeued, 0 if empty. */
int outbox_try_dequeue(char *out_text, size_t out_text_size);

/* outbox_count - how many messages are currently queued; used only for UI feedback, never load-bearing for correctness. */
int outbox_count(void);

#endif /* OUTBOX_H */

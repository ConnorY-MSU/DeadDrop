#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "outbox.h"

/* Fixed-size circular buffer of fixed-size string slots - simplest
 * correct implementation for a small, bounded queue; no dynamic
 * allocation, no linked-list bookkeeping. pthread is available
 * unconditionally on this project's two real targets (Linux natively,
 * this project's Windows dev machine via winpthreads - confirmed
 * working during the two-way redesign, see session.c/session.h),
 * so no __linux__ split is needed here. */
static char slots[OUTBOX_MAX_MESSAGES][OUTBOX_MSG_MAX_LEN];
static int head = 0;   /* next slot to dequeue from */
static int count = 0;  /* number of messages currently queued */
static pthread_mutex_t outbox_mutex = PTHREAD_MUTEX_INITIALIZER;

int outbox_enqueue(const char *text)
{
    int tail;

    if (text == NULL) {
        return -1;
    }

    pthread_mutex_lock(&outbox_mutex);

    if (count >= OUTBOX_MAX_MESSAGES) {
        pthread_mutex_unlock(&outbox_mutex);
        return -1; /* full - see this function's header comment */
    }

    tail = (head + count) % OUTBOX_MAX_MESSAGES;
    snprintf(slots[tail], OUTBOX_MSG_MAX_LEN, "%s", text);
    count++;

    pthread_mutex_unlock(&outbox_mutex);
    return 0;
}

int outbox_try_dequeue(char *out_text, size_t out_text_size)
{
    pthread_mutex_lock(&outbox_mutex);

    if (count == 0) {
        pthread_mutex_unlock(&outbox_mutex);
        return 0;
    }

    if (out_text != NULL && out_text_size > 0) {
        snprintf(out_text, out_text_size, "%s", slots[head]);
    }
    head = (head + 1) % OUTBOX_MAX_MESSAGES;
    count--;

    pthread_mutex_unlock(&outbox_mutex);
    return 1;
}

int outbox_count(void)
{
    int c;
    pthread_mutex_lock(&outbox_mutex);
    c = count;
    pthread_mutex_unlock(&outbox_mutex);
    return c;
}

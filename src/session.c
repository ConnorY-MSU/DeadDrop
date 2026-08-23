#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "session.h"
#include "message.h"
#include "hw_expansion.h"
#include "hw_oled.h"
#include "hw_tts.h"
#include "ui.h"
#include "outbox.h"
#include "msglog.h"

/* Platform bits this file needs beyond what session.h already brought in
 * (socket_t, winsock2.h on Windows). Kept local rather than folded into
 * session.h - session.h's callers don't need to know shutdown()
 * semantics, only this implementation does, same "platform knowledge
 * lives only where it's used" precedent client.c/server.c already set. */
#ifdef _WIN32
    #define SHUTDOWN_READ(s) shutdown((s), SD_RECEIVE)
    #include <direct.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <unistd.h>
    #define SHUTDOWN_READ(s) shutdown((s), SHUT_RD)
    #define MKDIR(path) mkdir((path), 0700)
#endif

/* How often the sender loop wakes up (if nothing's been typed) to
 * re-check whether the receiver thread has ended the session. Bounds the
 * worst-case delay between "peer disconnected" and this side noticing
 * and returning, when the local user hasn't typed anything. Also bounds
 * (on the real ncurses UI path) how long an incoming message's display
 * can be delayed by a concurrent ui_poll_line() wait - see ui.c's
 * ui_mutex comment. 200ms: responsive enough that neither delay is
 * perceptible, without busy-looping. Also the granularity at which the
 * periodic PING/RTT check below re-checks whether it's due. */
#define STDIN_POLL_MS 200

/* How often the sender loop sends a PING purely for a live RTT/link-
 * quality reading (see ui_report_rtt(), which feeds the OLED metrics
 * section). ALSO now doubles as the watchdog's own heartbeat interval -
 * see SESSION_WATCHDOG_TIMEOUT_SECONDS below - since the comment this
 * replaced ("session.c already detects a dead connection via
 * wolfSSL_read() returning <= 0, independent of this") turned out to be
 * WRONG for a genuinely silent peer loss (see that #define's own
 * comment for the real story, found via a live test). */
#define SESSION_PING_INTERVAL_SECONDS 10

/* REAL BUG FOUND AND FIXED (2026-08-22): a genuinely silent peer loss
 * (network cable pulled, power lost - no FIN/RST ever arrives, unlike a
 * graceful close/quit, which this project's code already detects
 * instantly via wolfSSL_read() returning <= 0) went undetected
 * INDEFINITELY - not just slowly, literally forever - despite
 * CONN_TIMEOUT_SECONDS (client.c/server.c, 30s) being set via
 * SO_RCVTIMEO on the raw socket. Root-caused via a live test (an
 * iptables DROP rule silently discarding all traffic to/from the peer,
 * simulating a real unplug) plus gdb (confirmed the receiver thread
 * genuinely blocked inside the kernel's own recv() syscall, 80+ seconds
 * in) plus a direct getsockopt() check (confirmed SO_RCVTIMEO really
 * was 30s at handshake time - the value itself was never wrong). The
 * actual cause: clear_recv_timeout() (below) deliberately RESETS
 * SO_RCVTIMEO to 0 (block indefinitely) the moment a session goes live,
 * specifically so a normal idle chat session doesn't spuriously
 * disconnect every 30s of real silence - a genuinely correct design
 * choice for the "peer is fine, just not talking right now" case, which
 * simply has no read timeout left at all for the "peer's network
 * silently died" case. An earlier attempt at fixing this by calling
 * wolfSSL_set_using_nonblock() (based on a wolfSSL WANT_READ/blocking-
 * socket quirk that seemed plausible at the time) did NOT help, because
 * it was solving for the wrong layer - there was no timeout event to
 * surface in the first place.
 *
 * Fixed with an explicit application-level watchdog instead of relying
 * on the OS socket timeout for this: the sender loop already wakes up
 * regularly to send a periodic PING (SESSION_PING_INTERVAL_SECONDS)
 * purely for RTT reporting - it now ALSO checks how long it's been
 * since ANY data was actually received from the peer
 * (ctx.last_recv_epoch, updated by the receiver thread on every
 * successfully parsed message - see receiver_thread_main()). If that
 * exceeds this timeout, the sender loop forcibly calls SHUTDOWN_READ()
 * on the raw socket - the EXACT SAME mechanism this file already uses
 * to unblock a receiver thread stuck in a blocking read when the LOCAL
 * user quits (see this function's other SHUTDOWN_READ() call) - which
 * guarantees the blocked recv() returns immediately, REGARDLESS of
 * wolfSSL's internal retry behavior, since a shutdown() on the read
 * side of a socket is a hard, unconditional OS-level guarantee, not
 * something that depends on getting wolfSSL's blocking/non-blocking
 * semantics exactly right. Set to less than 3 PING intervals - long
 * enough that a single lost PING or a slow link doesn't cause a false
 * disconnect, short enough that a real loss is caught in well under a
 * minute rather than never. */
#define SESSION_WATCHDOG_TIMEOUT_SECONDS 25

/*
 * clear_recv_timeout - undo client.c/server.c's pre-handshake SO_RCVTIMEO
 * (CONN_TIMEOUT_SECONDS) on the raw socket. See session.h's "IMPORTANT
 * for callers" comment above run_symmetric_session() for the full
 * reasoning: that timeout exists to bound a stalled connect/handshake,
 * but a receiver thread legitimately blocking in wolfSSL_read() for a
 * long time during an idle chat is normal, not a failure - leaving the
 * old timeout in place would silently disconnect and reconnect roughly
 * every CONN_TIMEOUT_SECONDS of real idle time. A value of 0 means "no
 * timeout, block indefinitely" on both Windows and POSIX. SO_SNDTIMEO is
 * deliberately left alone - see the header comment. */
static void clear_recv_timeout(socket_t s)
{
#ifdef _WIN32
    DWORD timeout_ms = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

/* monotonic_now - clock_gettime(CLOCK_MONOTONIC), returned as a plain
 * struct timespec. Used for both the periodic-PING interval check and
 * RTT measurement. Confirmed working on both this project's real
 * targets (native Linux, and this project's Windows/UCRT64 dev machine)
 * during Week 3 Day 4's benchmark.c work - not a new, unverified
 * assumption. */
static struct timespec monotonic_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}

static double ms_between(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1.0e6;
}

/* --- Shared state between the two threads ----------------------------
 *
 * See session.h's design comment for the full reasoning on why sends
 * need a mutex around the whole serialize+write pair while parses need
 * none at all.
 */
#define SESSION_PENDING_ACK_MAX 8      /* how many of OUR OWN recently-
    sent TEXT_MESSAGEs we track waiting for their ACK - bounded, not
    unbounded: a circular buffer, oldest untracked entries are simply no
    longer confirmable by name once evicted (an ACK for one of those
    still arrives and is harmlessly ignored - see consume_pending_ack()),
    which is an acceptable, honestly-scoped limit for what is fundamentally
    a nice-to-have delivery indicator, not a guaranteed-exactly-once
    tracking system. */
#define SESSION_ACK_PREVIEW_LEN 48

typedef struct {
    uint32_t seq_num;
    char     preview[SESSION_ACK_PREVIEW_LEN];
    int      active;
} pending_ack_entry;

typedef struct {
    sl_session_state *state;
    WOLFSSL *ssl_read;   /* original object, read-only after write_dup -
                           * used only by the receiver thread */
    WOLFSSL *ssl_write;  /* write_dup()'d object - used by BOTH threads
                           * (local user sends, receiver's PONG/ACK auto-
                           * replies), protected by send_mutex */
    pthread_mutex_t send_mutex;

    /* Also protected by send_mutex (reused rather than adding a second
     * lock for two small pieces of state that are only ever touched
     * from inside/around the same critical sections session_send()
     * already takes) - see session_send()'s and the two helper
     * functions' comments below. */
    pending_ack_entry pending_acks[SESSION_PENDING_ACK_MAX];
    int pending_ack_next_slot;
    int ping_outstanding;
    struct timespec ping_sent_at;

    volatile int peer_ended;  /* set by the receiver thread once IT
                                * decides the session is over (peer
                                * DISCONNECT, read error/close, or an
                                * invalid message) */
    volatile long last_recv_epoch; /* time(NULL) as of the last message
                                * successfully received from the peer -
                                * see SESSION_WATCHDOG_TIMEOUT_SECONDS'
                                * comment for why this exists: written by
                                * the receiver thread, read by the sender
                                * loop, a single word so a lockless
                                * read/write pair is fine for a liveness
                                * heuristic (not a correctness-critical
                                * value) */
    volatile int should_stop; /* set by the main thread once IT decides
                                * the session is over (user quit/EOF) -
                                * documentation of intent; shutdown() on
                                * the raw socket is the actual mechanism
                                * that unblocks a receiver thread sitting
                                * in a blocking read */

    int hw_fd;   /* connection-level RGB status is still owned by the
                  * caller (client.c/server.c's connect loop) - this is
                  * used only for the message-pending flash (see
                  * ui_notify_message_pending()), below. */
    int oled_fd;
    const char *peer_label;
} shared_session_ctx;

static void seq_num_to_be(uint32_t seq, uint8_t out[4])
{
    out[0] = (uint8_t)(seq >> 24);
    out[1] = (uint8_t)(seq >> 16);
    out[2] = (uint8_t)(seq >> 8);
    out[3] = (uint8_t)(seq);
}

static uint32_t be_to_seq_num(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

/* --- Shared send helper: used by BOTH threads -------------------------
 *
 * Holds send_mutex across the ENTIRE serialize+write pair - see
 * session.h's design comment for why splitting those into two separate
 * critical sections would be a real ordering/corruption bug, not just a
 * style choice.
 *
 * out_seq_num (may be NULL): if non-NULL, filled with the seq_num this
 * specific send actually used - the caller cannot safely read
 * ctx->state->next_seq_num itself before/after this call (another
 * thread could send concurrently in between, e.g. the receiver thread
 * auto-replying with PONG/ACK while the main thread is mid-send), so
 * this is the only race-free way to know which seq_num a given send
 * consumed. Used for ACK-tracking a TEXT_MESSAGE - see
 * track_pending_ack() below.
 */
static int session_send(shared_session_ctx *ctx, uint8_t msg_type,
                         const uint8_t *body, uint32_t body_len,
                         uint32_t *out_seq_num)
{
    uint8_t out_buf[SL_MAX_MSG_SIZE];
    int total;
    int rc;
    uint32_t used_seq_num;

    pthread_mutex_lock(&ctx->send_mutex);

    used_seq_num = ctx->state->next_seq_num; /* captured BEFORE
        serialize consumes it, still under the lock - race-free */

    total = sl_serialize_message(ctx->state, msg_type, body, body_len,
                                  out_buf, sizeof(out_buf));
    if (total < 0) {
        pthread_mutex_unlock(&ctx->send_mutex);
        ui_add_errorf("(send failed: message too large, "
                       "body_len=%u)", body_len);
        return -1;
    }

    rc = wolfSSL_write(ctx->ssl_write, out_buf, total);

    /* Record the outstanding PING's send time while still holding the
     * lock - the only other writer/reader of these two fields
     * (check_and_clear_ping(), called from the receiver thread on PONG
     * receipt) also takes this same lock, so there's no race even
     * though this is "extra" work tucked inside a function whose name
     * doesn't mention PING. */
    if (msg_type == SL_MSG_PING && rc == total) {
        ctx->ping_outstanding = 1;
        ctx->ping_sent_at = monotonic_now();
    }

    pthread_mutex_unlock(&ctx->send_mutex);

    if (rc != total) {
        int err = wolfSSL_get_error(ctx->ssl_write, rc);
        char errbuf[80];
        ui_add_errorf("(send failed: %s)",
                       wolfSSL_ERR_error_string(err, errbuf));
        return -1;
    }
    if (out_seq_num != NULL) {
        *out_seq_num = used_seq_num;
    }
    return 0;
}

/* track_pending_ack - remember that we just sent a TEXT_MESSAGE with
 * this seq_num/preview, so a later ACK referencing it can show a
 * meaningful "(delivered: "...")" confirmation. Circular buffer -
 * see SESSION_PENDING_ACK_MAX's comment. */
static void track_pending_ack(shared_session_ctx *ctx, uint32_t seq_num,
                               const char *text)
{
    pending_ack_entry *e;

    pthread_mutex_lock(&ctx->send_mutex);
    e = &ctx->pending_acks[ctx->pending_ack_next_slot];
    e->seq_num = seq_num;
    snprintf(e->preview, sizeof(e->preview), "%s", text);
    e->active = 1;
    ctx->pending_ack_next_slot =
        (ctx->pending_ack_next_slot + 1) % SESSION_PENDING_ACK_MAX;
    pthread_mutex_unlock(&ctx->send_mutex);
}

/* consume_pending_ack - look up and consume (mark inactive) a pending
 * entry for the given seq_num. Returns 1 and fills out_preview if
 * found, 0 otherwise (a perfectly normal outcome - see
 * SESSION_PENDING_ACK_MAX's comment on eviction; also normal for an ACK
 * that doesn't correspond to a TEXT_MESSAGE we're actively tracking for
 * any other reason). */
static int consume_pending_ack(shared_session_ctx *ctx, uint32_t seq_num,
                                char *out_preview, size_t out_preview_size)
{
    int i;
    int found = 0;

    pthread_mutex_lock(&ctx->send_mutex);
    for (i = 0; i < SESSION_PENDING_ACK_MAX; i++) {
        pending_ack_entry *e = &ctx->pending_acks[i];
        if (e->active && e->seq_num == seq_num) {
            snprintf(out_preview, out_preview_size, "%s", e->preview);
            e->active = 0;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->send_mutex);
    return found;
}

/* check_and_clear_ping - if a PING is currently outstanding, compute the
 * elapsed time since it was sent, clear the outstanding flag, and
 * return 1 with *out_rtt_ms filled in. Returns 0 (no-op) if no PING was
 * outstanding - a PONG can legitimately arrive with none outstanding
 * (e.g. this is a reply to the PEER's own periodic PING, which our
 * receiver auto-replied to, and the peer's PONG-back-to-us case doesn't
 * apply here since PONG is never itself PONG-replied-to - this really
 * only guards against an unexpected/duplicate PONG, not a normal
 * scenario). */
static int check_and_clear_ping(shared_session_ctx *ctx, double *out_rtt_ms)
{
    int had_one;

    pthread_mutex_lock(&ctx->send_mutex);
    had_one = ctx->ping_outstanding;
    if (had_one) {
        *out_rtt_ms = ms_between(ctx->ping_sent_at, monotonic_now());
        ctx->ping_outstanding = 0;
    }
    pthread_mutex_unlock(&ctx->send_mutex);
    return had_one;
}

/* --- Received-file handling ---------------------------------------- */

/* Same directory the PIN hash and message log already use
 * ($HOME/.securelink/) so it rides along on the exact same, already-
 * persisted (Week 4 Day 5) bind mount with zero changes needed to
 * docs/setup-persist-overlay.sh - see msglog.c's matching comment. */
static int received_files_dir(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (home == NULL) {
        home = getenv("USERPROFILE");
    }
#endif
    if (home == NULL) {
        return -1;
    }
    if ((size_t)snprintf(buf, buf_size, "%s/.securelink/received", home)
            >= buf_size) {
        return -1;
    }
    return 0;
}

static void ensure_dir_exists(const char *dir)
{
    /* MKDIR on an already-existing directory failing is fine and
     * expected on every call after the first - not checked, matching
     * lock.c's/msglog.c's own precedent for this exact situation. */
    MKDIR(dir);
}

/* sanitize_basename - strip any directory components (both '/' and
 * '\\' - the peer's OS isn't assumed) from an attacker-influenceable
 * (it arrived over the wire) filename, and refuse "." or ".." outright,
 * so it can never be used to escape received_files_dir() via path
 * traversal. Falls back to a generic name if nothing usable remains -
 * same "validate untrusted input, never trust it as-is" discipline
 * already established elsewhere in this project (wifi.c's execvp-not-
 * shell reasoning, the revocation module's fail-closed default). */
static void sanitize_basename(const char *raw, char *out, size_t out_size)
{
    const char *p = raw;
    const char *last_sep = NULL;

    for (; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            last_sep = p;
        }
    }
    if (last_sep != NULL) {
        raw = last_sep + 1;
    }

    if (raw[0] == '\0' || strcmp(raw, ".") == 0 || strcmp(raw, "..") == 0) {
        snprintf(out, out_size, "received_file_%ld", (long)time(NULL));
        return;
    }
    snprintf(out, out_size, "%s", raw);
}

/* --- Receiver thread ---------------------------------------------------
 *
 * Runs for the whole session: always reads, parses, displays, and (for
 * PING/TEXT_MESSAGE only) auto-replies, regardless of whether the local
 * user is actively typing right now - "receiving always works, replying
 * is optional". Never blocks the sender: its wolfSSL_read() call runs on
 * ssl_read, entirely separate from the ssl_write object the sender uses.
 */
typedef enum {
    RTHREAD_RECV_OK,
    RTHREAD_RECV_REJECTED,
    RTHREAD_RECV_CLOSED
} rthread_recv_status;

static rthread_recv_status receiver_recv_one(WOLFSSL *ssl_read,
                                              sl_session_state *state,
                                              uint8_t *recv_buf, size_t *have,
                                              sl_parsed_message *out_msg)
{
    for (;;) {
        size_t consumed = 0;
        sl_parse_result pr = sl_try_parse_message(state, recv_buf, *have,
                                                   out_msg, &consumed);

        if (pr == SL_PARSE_OK) {
            memmove(recv_buf, recv_buf + consumed, *have - consumed);
            *have -= consumed;
            return RTHREAD_RECV_OK;
        }
        if (pr == SL_PARSE_REJECTED) {
            if (consumed > 0) {
                memmove(recv_buf, recv_buf + consumed, *have - consumed);
                *have -= consumed;
            }
            return RTHREAD_RECV_REJECTED;
        }

        if (*have >= SL_MAX_MSG_SIZE) {
            return RTHREAD_RECV_REJECTED;
        }

        {
            int n = wolfSSL_read(ssl_read, (char *)(recv_buf + *have),
                                  (int)(SL_MAX_MSG_SIZE - *have));
            if (n <= 0) {
                /* Covers both a real peer-side close/error AND the
                 * deliberate local shutdown(sock, SHUT_RD) used to
                 * unblock this thread when the LOCAL user quit - either
                 * way this thread's job is done. run_symmetric_session
                 * already knows independently which of those two
                 * reasons applies (it initiated the local-quit case
                 * itself) and decides its own return value accordingly,
                 * so this function doesn't need to distinguish them. */
                return RTHREAD_RECV_CLOSED;
            }
            *have += (size_t)n;
        }
    }
}

static void *receiver_thread_main(void *arg)
{
    shared_session_ctx *ctx = (shared_session_ctx *)arg;
    uint8_t *recv_buf = malloc(SL_MAX_MSG_SIZE);
    /* Full-length NUL-terminated copy of a TEXT_MESSAGE body, for
     * ui_add_history()/ui_add_historyf() (which need a real C string) -
     * deliberately separate from the short OLED/TTS preview[] below:
     * the on-screen history should show the whole message, not a
     * 21-character-wide truncation. */
    char *text_buf = malloc(SL_MAX_BODY_LEN + 1);
    size_t have = 0;

    if (recv_buf == NULL || text_buf == NULL) {
        free(recv_buf);
        free(text_buf);
        ui_add_error("(internal error: out of memory)");
        ctx->peer_ended = 1;
        return NULL;
    }

    for (;;) {
        sl_parsed_message msg;
        rthread_recv_status rs = receiver_recv_one(ctx->ssl_read, ctx->state,
                                                     recv_buf, &have, &msg);

        if (rs == RTHREAD_RECV_CLOSED) {
            ctx->peer_ended = 1;
            break;
        }
        if (rs == RTHREAD_RECV_REJECTED) {
            ui_add_errorf("Received an invalid message from %s "
                           "- ending session.", ctx->peer_label);
            ctx->peer_ended = 1;
            break;
        }

        /* rs == RTHREAD_RECV_OK - the peer is demonstrably alive, having
         * just sent something real (a TEXT_MESSAGE, ACK, PING, PONG,
         * FILE, or DISCONNECT - any recognized message type at all).
         * See SESSION_WATCHDOG_TIMEOUT_SECONDS' comment for why this
         * matters: this is the ONLY place last_recv_epoch gets updated. */
        ctx->last_recv_epoch = (long)time(NULL);

        if (msg.msg_type == SL_MSG_TEXT_MESSAGE) {
            /* msg.body is length-prefixed per PROTOCOL.md, NOT a
             * NUL-terminated C string - every consumer below needs a
             * real C string, so a NUL-terminated copy is made first.
             * text_buf is the full message (sized SL_MAX_BODY_LEN+1,
             * see its declaration above), for the on-screen history;
             * preview[] below is a SEPARATE, much shorter copy for the
             * 21-character-wide OLED and for speech, where a full 64KB
             * message would be its own bad idea regardless of
             * hw_tts_speak()'s own internal cap. */
            {
                size_t n = msg.body_len;
                if (n > SL_MAX_BODY_LEN) {
                    n = SL_MAX_BODY_LEN; /* defensive; the protocol layer
                                           * already enforces this cap */
                }
                memcpy(text_buf, msg.body, n);
                text_buf[n] = '\0';
            }
            ui_add_history(ctx->peer_label, text_buf);
            ui_notify_message_pending(ctx->hw_fd);
            msglog_append(ctx->peer_label, text_buf);

            /* Automatic delivery acknowledgment - see PROTOCOL.md's
             * ACK entry. Same "auto-reply is fatal on failure" pattern
             * as the existing PING->PONG reply below - a failure here
             * means the connection is almost certainly already dead. */
            {
                uint8_t ack_body[4];
                seq_num_to_be(msg.seq_num, ack_body);
                if (session_send(ctx, SL_MSG_ACK, ack_body,
                                  sizeof(ack_body), NULL) != 0) {
                    ctx->peer_ended = 1;
                    break;
                }
            }

            {
                char preview[64];
                size_t preview_len = msg.body_len;
                if (preview_len > sizeof(preview) - 1) {
                    preview_len = sizeof(preview) - 1;
                }
                memcpy(preview, msg.body, preview_len);
                preview[preview_len] = '\0';

                {
                    char oled_line0[32];
                    snprintf(oled_line0, sizeof(oled_line0), "From %s:",
                              ctx->peer_label);
                    hw_oled_draw_text(ctx->oled_fd, 0, oled_line0);
                    hw_oled_draw_text(ctx->oled_fd, 1, preview);
                    hw_oled_display(ctx->oled_fd);
                }
                hw_tts_speak(preview);
            }
        } else if (msg.msg_type == SL_MSG_ACK) {
            if (msg.body_len == 4) {
                uint32_t acked_seq = be_to_seq_num(msg.body);
                char preview[SESSION_ACK_PREVIEW_LEN];
                if (consume_pending_ack(ctx, acked_seq, preview,
                                         sizeof(preview))) {
                    ui_add_historyf(NULL, "(delivered: \"%s\")", preview);
                }
                /* Not found: a perfectly normal outcome (eviction, or
                 * an ACK for something we weren't tracking) - see
                 * consume_pending_ack()'s comment. Silently ignored,
                 * not an error. */
            }
        } else if (msg.msg_type == SL_MSG_FILE) {
            if (msg.body_len < SL_FILE_NAME_LEN_SIZE) {
                /* Malformed - too short to even hold the length prefix.
                 * sl_try_parse_message() already validated the HMAC
                 * over this body, so this isn't a tampering concern,
                 * just a peer (or a peer's bug) sending a nonsensical
                 * FILE message - ignore rather than tear down the
                 * whole session over it. */
            } else {
                uint16_t name_len = (uint16_t)((msg.body[0] << 8) |
                                                 msg.body[1]);
                if (name_len > SL_FILE_NAME_MAX ||
                    (size_t)(SL_FILE_NAME_LEN_SIZE + name_len) >
                        msg.body_len) {
                    /* Malformed - name_len claims more than the body
                     * actually holds. Same "ignore, don't tear down
                     * the session" handling as above. */
                } else {
                    char raw_name[SL_FILE_NAME_MAX + 1];
                    char safe_name[SL_FILE_NAME_MAX + 1];
                    const uint8_t *data = msg.body + SL_FILE_NAME_LEN_SIZE +
                                            name_len;
                    size_t data_len = msg.body_len -
                        (SL_FILE_NAME_LEN_SIZE + name_len);
                    char dir[512];
                    char path[768];

                    memcpy(raw_name, msg.body + SL_FILE_NAME_LEN_SIZE,
                            name_len);
                    raw_name[name_len] = '\0';
                    sanitize_basename(raw_name, safe_name,
                                        sizeof(safe_name));

                    if (received_files_dir(dir, sizeof(dir)) == 0) {
                        ensure_dir_exists(dir);
                        snprintf(path, sizeof(path), "%s/%s", dir,
                                  safe_name);

                        {
                            FILE *f = fopen(path, "wb");
                            if (f != NULL) {
                                size_t written = fwrite(data, 1, data_len, f);
                                fclose(f);
                                if (written == data_len) {
                                    ui_add_historyf(ctx->peer_label,
                                        "sent a file: %s (%u bytes) -> "
                                        "saved to ~/.securelink/received/",
                                        safe_name, (unsigned)data_len);
                                    msglog_append(ctx->peer_label,
                                        "(sent a file - see "
                                        "~/.securelink/received/)");
                                    ui_notify_message_pending(ctx->hw_fd);
                                } else {
                                    ui_add_errorf(
                                        "(failed to fully write received "
                                        "file %s)", safe_name);
                                }
                            } else {
                                ui_add_errorf(
                                    "(failed to save received file %s)",
                                    safe_name);
                            }
                        }
                    }
                }
            }
        } else if (msg.msg_type == SL_MSG_PING) {
            /* No history notice - see SESSION_PING_INTERVAL_SECONDS's
             * comment: PING is now a routine, automatic, ~10s
             * background event, not a rare occurrence worth chat-log
             * noise. Same "fatal on auto-reply failure" pattern as
             * ACK's send above. */
            if (session_send(ctx, SL_MSG_PONG, NULL, 0, NULL) != 0) {
                ctx->peer_ended = 1;
                break;
            }
        } else if (msg.msg_type == SL_MSG_PONG) {
            /* Also no history notice, same reasoning - this is the
             * live RTT/link-quality reading, reported to the OLED
             * metrics section (ui_report_rtt()), not the chat log. */
            double rtt_ms;
            if (check_and_clear_ping(ctx, &rtt_ms)) {
                ui_report_rtt((int)rtt_ms);
            }
        } else if (msg.msg_type == SL_MSG_DISCONNECT) {
            ui_add_historyf(NULL, "%s sent DISCONNECT.", ctx->peer_label);
            ctx->peer_ended = 1;
            break;
        }
        /* Any other well-formed-but-unrecognized msg_type: treated as
         * forward-compat noise, not fatal - sl_try_parse_message() has
         * already validated version/HMAC/seq_num by this point. */
    }

    free(recv_buf);
    free(text_buf);
    return NULL;
}

/* --- Public entry point ------------------------------------------------ */

session_result run_symmetric_session(WOLFSSL *ssl, socket_t sock, int hw_fd,
                                      int oled_fd, const char *peer_label)
{
    sl_session_state state;
    shared_session_ctx ctx;
    pthread_t rtid;
    char *line;
    char *file_body; /* scratch buffer for building an outgoing
        SL_MSG_FILE body ("/send <path>") - see below. Separate from
        `line` (which holds the typed "/send <path>" COMMAND text
        itself, not the file's own binary content). */
    struct timespec last_ping_sent;
    session_result result;

    if (sl_session_init(ssl, &state) != 0) {
        ui_add_error(
            "sl_session_init failed - wolfSSL_export_keying_material "
            "unavailable? (needs HAVE_KEYING_MATERIAL / "
            "--enable-keying-material)");
        return SESSION_DISCONNECTED;
    }

    /* See session.h's "IMPORTANT for callers" comment: must happen before
     * the receiver thread starts blocking in wolfSSL_read(), or it could
     * legitimately hit the old pre-handshake timeout during its very
     * first idle wait. */
    clear_recv_timeout(sock);

    ctx.state = &state;
    ctx.ssl_read = ssl;

    /* wolfSSL_write_dup() turns `ssl` into a read-only object and hands
     * back a genuinely separate write-only object - this is the actual
     * safety mechanism that makes concurrent read (receiver thread) and
     * write (either thread, via session_send) on this session safe at
     * all. Needs HAVE_WRITE_DUP / --enable-writedup - see docs/BUILD.md. */
    ctx.ssl_write = wolfSSL_write_dup(ssl);
    if (ctx.ssl_write == NULL) {
        ui_add_error(
            "wolfSSL_write_dup failed - this wolfSSL build may lack "
            "HAVE_WRITE_DUP / --enable-writedup");
        return SESSION_DISCONNECTED;
    }

    pthread_mutex_init(&ctx.send_mutex, NULL);
    memset(ctx.pending_acks, 0, sizeof(ctx.pending_acks));
    ctx.pending_ack_next_slot = 0;
    ctx.ping_outstanding = 0;
    ctx.peer_ended = 0;
    ctx.should_stop = 0;
    /* Starts "now," not 0 - see SESSION_WATCHDOG_TIMEOUT_SECONDS'
     * comment. Without this, a fresh session with a slightly slow first
     * PONG could spuriously look like it's already been silent since
     * epoch 0, an enormous (and wrong) duration. */
    ctx.last_recv_epoch = (long)time(NULL);
    ctx.hw_fd = hw_fd;
    ctx.oled_fd = oled_fd;
    ctx.peer_label = peer_label;

    if (pthread_create(&rtid, NULL, receiver_thread_main, &ctx) != 0) {
        ui_add_error("run_symmetric_session: pthread_create failed");
        pthread_mutex_destroy(&ctx.send_mutex);
        wolfSSL_free(ctx.ssl_write);
        return SESSION_DISCONNECTED;
    }

    /* Same SL_MAX_BODY_LEN-sized stack buffer client.c's old
     * run_interactive_session() used for a typed line - heap-allocated
     * here instead since this function's stack frame now also holds
     * shared_session_ctx and sl_session_state, and a 64KB fixed stack
     * buffer on top of those is unnecessary pressure for no benefit. */
    line = malloc(SL_MAX_BODY_LEN);
    file_body = malloc(SL_MAX_BODY_LEN);
    if (line == NULL || file_body == NULL) {
        ui_add_error("run_symmetric_session: out of memory");
        free(line);
        free(file_body);
        ctx.should_stop = 1;
        SHUTDOWN_READ(sock);
        pthread_join(rtid, NULL);
        pthread_mutex_destroy(&ctx.send_mutex);
        wolfSSL_free(ctx.ssl_write);
        return SESSION_DISCONNECTED;
    }

    ui_set_statusf("Connected to %s", peer_label);
    /* No per-connection instructional hint here anymore (2026-08-22,
     * direct request) - this used to print the full "type a message..."
     * paragraph on EVERY connect/reconnect, which meant a flaky link
     * doing several reconnect cycles spammed the same instructions
     * repeatedly. The guide is now shown once at boot (ui_init()) and
     * on demand via the new "/help" command below - see ui_show_help(). */

    /* Drain anything queued while offline (see outbox.h) now that a
     * real session exists to send through - same TEXT_MESSAGE send +
     * ack-tracking + persistence + history-echo treatment as a message
     * typed live, just sourced from the queue instead of ui_poll_line().
     * Runs once, right at session start, before the first real
     * ui_poll_line() wait - if this is a long queue, sending it out
     * takes a moment, which is fine (a handful of tiny TEXT_MESSAGEs is
     * fast) and matches user expectation ("my queued messages went out
     * as soon as I reconnected"). */
    {
        char queued[OUTBOX_MSG_MAX_LEN];
        while (outbox_try_dequeue(queued, sizeof(queued))) {
            uint32_t sent_seq;
            size_t qlen = strlen(queued);
            if (session_send(&ctx, SL_MSG_TEXT_MESSAGE,
                              (const uint8_t *)queued, (uint32_t)qlen,
                              &sent_seq) == 0) {
                track_pending_ack(&ctx, sent_seq, queued);
                msglog_append("you", queued);
                ui_add_history("you", queued);
            } else {
                /* Send failed mid-drain (connection died again) - put
                 * it back at the front of the queue rather than lose
                 * it, and stop draining; the next successful session
                 * start will pick up where this left off. */
                outbox_enqueue(queued);
                break;
            }
        }
    }

    last_ping_sent = monotonic_now();

    for (;;) {
        size_t len;
        ui_poll_result pr;

        if (ctx.peer_ended) {
            ui_add_historyf(NULL, "Connection to %s lost.", peer_label);
            result = SESSION_DISCONNECTED;
            break;
        }

        /* Periodic PING purely for the live RTT/link-quality reading -
         * see SESSION_PING_INTERVAL_SECONDS's comment. Checked once per
         * loop iteration (every up-to-STDIN_POLL_MS), which is plenty
         * granular for a 10-second interval. Skips sending a new one if
         * the previous PING never got a PONG back yet, rather than
         * letting them stack up during a slow/degraded link - the next
         * PING attempt (after this one's own outstanding flag would
         * have been cleared by a timeout... actually there is no
         * explicit PING timeout here: an outstanding PING that never
         * gets a PONG simply means no fresh RTT sample until the next
         * successful round-trip, which is an honest reflection of link
         * quality, not a bug to work around). */
        {
            struct timespec now_ts = monotonic_now();
            if (ms_between(last_ping_sent, now_ts) >=
                    SESSION_PING_INTERVAL_SECONDS * 1000.0) {
                int outstanding;
                pthread_mutex_lock(&ctx.send_mutex);
                outstanding = ctx.ping_outstanding;
                pthread_mutex_unlock(&ctx.send_mutex);
                if (!outstanding) {
                    session_send(&ctx, SL_MSG_PING, NULL, 0, NULL);
                }
                last_ping_sent = now_ts;
            }
        }

        /* Watchdog: forcibly end the session if nothing at all has been
         * received from the peer in too long - see
         * SESSION_WATCHDOG_TIMEOUT_SECONDS' comment for the full story
         * on why this exists (a genuinely silent peer loss otherwise
         * hangs forever, not just slowly, since the OS-level read
         * timeout is deliberately disabled once a session is live).
         * SHUTDOWN_READ() unblocks the receiver thread's blocked read
         * immediately and unconditionally - the same mechanism this
         * function already uses below for a local user quit - which
         * then sets ctx.peer_ended itself; this loop's own peer_ended
         * check at the top catches that on the very next iteration, so
         * this doesn't need its own separate "already triggered" guard. */
        if ((long)time(NULL) - ctx.last_recv_epoch >=
                SESSION_WATCHDOG_TIMEOUT_SECONDS) {
            SHUTDOWN_READ(sock);
        }

        pr = ui_poll_line(line, SL_MAX_BODY_LEN, STDIN_POLL_MS);

        if (pr == UI_POLL_TIMEOUT) {
            continue;
        }
        if (pr == UI_POLL_QUIT) {
            /* stdin closed (EOF) - only the plain-console fallback ever
             * returns this; see ui.h. Treat the same as an explicit
             * quit. */
            ui_add_history(NULL, "(you quit)");
            session_send(&ctx, SL_MSG_DISCONNECT, NULL, 0, NULL);
            result = SESSION_USER_QUIT;
            break;
        }

        /* pr == UI_POLL_LINE: line[] holds the composed, NUL-terminated
         * line (any trailing newline already stripped by ui_poll_line()). */
        len = strlen(line);

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            ui_add_history(NULL, "(you quit)");
            session_send(&ctx, SL_MSG_DISCONNECT, NULL, 0, NULL);
            result = SESSION_USER_QUIT;
            break;
        }

        /* "/clear" - a purely LOCAL command (never sent to the peer -
         * this device's own copy of the chat is all it can honestly
         * promise to zero; the peer keeps their own separate copy
         * regardless). Checked before the ctx.peer_ended check below,
         * same reasoning as "quit"/"exit" above: this doesn't need a
         * live connection to do its job. See msglog.h's
         * msglog_clear_except_saved() and ui.h's ui_clear_history() for
         * what each half actually does - together they zero both the
         * on-disk log and the on-screen scrollback, keeping only
         * whatever was previously sent via "/save <text>" below. */
        if (strcmp(line, "/clear") == 0) {
            msglog_clear_except_saved();
            ui_clear_history();
            ui_add_history(NULL,
                "(chat cleared - any /save'd messages were kept)");
            continue;
        }

        /* "/help" - same purely-local, no-connection-needed reasoning as
         * "/clear" above. Re-prints the exact guide ui_init() already
         * shows once at boot (see ui_show_help()) - this is what replaced
         * the old per-connection instructional hint (see this function's
         * top comment). */
        if (strcmp(line, "/help") == 0) {
            ui_show_help();
            continue;
        }

        if (ctx.peer_ended) {
            /* Peer ended the session while this line was being typed -
             * don't bother sending into an already-dead connection.
             * Queue it instead of silently dropping it - it'll go out
             * automatically once a new session starts (see the outbox
             * drain above). */
            outbox_enqueue(line);
            ui_add_historyf(NULL, "Connection to %s lost. Your message "
                                   "has been queued.", peer_label);
            result = SESSION_DISCONNECTED;
            break;
        }

        /* "/save <text>" - sends a normal TEXT_MESSAGE, same as typing
         * the text alone would, EXCEPT it's also logged with the
         * "[SAVED]" marker (msglog_append_saved(), not the usual
         * msglog_append()) so a later "/clear" (above) keeps it instead
         * of discarding it. Deliberately scoped to messages sent FROM
         * this device, going forward - there's no way to retroactively
         * mark an already-sent or already-received message as saved
         * with this v1, a documented, honest limitation rather than an
         * oversight (the append-only log has no cheap way to find and
         * rewrite one specific earlier line without the same rewrite
         * machinery msglog_clear_except_saved() already needs for a
         * very different purpose). */
        if (len > 6 && strncmp(line, "/save ", 6) == 0) {
            const char *text = line + 6;
            uint32_t sent_seq;

            if (session_send(&ctx, SL_MSG_TEXT_MESSAGE,
                              (const uint8_t *)text, (uint32_t)strlen(text),
                              &sent_seq) != 0) {
                outbox_enqueue(text); /* the SAVED tag itself doesn't
                    survive an offline-queue retry - see this block's
                    comment above on why that's an accepted limitation,
                    not attempted here either */
                result = SESSION_DISCONNECTED;
                break;
            }
            track_pending_ack(&ctx, sent_seq, text);
            msglog_append_saved("you", text);
            ui_add_historyf("you", "[SAVED] %s", text);
            continue;
        }

        /* "/send <path>" - a small local file, read from THIS device's
         * own filesystem and transmitted as one SL_MSG_FILE. See
         * PROTOCOL.md's FILE entry for the hard size cap and why there
         * is no chunking - a file that doesn't fit is rejected here,
         * before anything is sent, not partway through. */
        if (len > 6 && strncmp(line, "/send ", 6) == 0) {
            const char *filepath = line + 6;
            FILE *f = fopen(filepath, "rb");

            if (f == NULL) {
                ui_add_errorf("(/send failed: cannot open '%s')",
                               filepath);
                continue;
            }

            {
                /* Basename of the LOCAL path, sent as the filename
                 * label - same sanitize_basename() used on the
                 * receiving end for symmetry/consistency, even though
                 * this is our own trusted local path, not untrusted
                 * wire input, here. */
                char name[SL_FILE_NAME_MAX + 1];
                size_t name_len;
                long file_size;
                size_t max_data;

                sanitize_basename(filepath, name, sizeof(name));
                name_len = strlen(name);

                fseek(f, 0, SEEK_END);
                file_size = ftell(f);
                fseek(f, 0, SEEK_SET);

                max_data = SL_MAX_BODY_LEN - SL_FILE_NAME_LEN_SIZE -
                           name_len;
                if (file_size < 0 || (size_t)file_size > max_data) {
                    fclose(f);
                    ui_add_errorf(
                        "(/send failed: '%s' is %ld bytes, max is %lu "
                        "bytes for a single-message file transfer)",
                        filepath, file_size, (unsigned long)max_data);
                    continue;
                }

                file_body[0] = (uint8_t)(name_len >> 8);
                file_body[1] = (uint8_t)(name_len);
                memcpy(file_body + SL_FILE_NAME_LEN_SIZE, name, name_len);
                {
                    size_t got = fread(
                        file_body + SL_FILE_NAME_LEN_SIZE + name_len,
                        1, (size_t)file_size, f);
                    fclose(f);
                    if (got != (size_t)file_size) {
                        ui_add_errorf(
                            "(/send failed: could not fully read '%s')",
                            filepath);
                        continue;
                    }
                }

                if (session_send(&ctx, SL_MSG_FILE, (uint8_t *)file_body,
                                  (uint32_t)(SL_FILE_NAME_LEN_SIZE +
                                             name_len + (size_t)file_size),
                                  NULL) != 0) {
                    result = SESSION_DISCONNECTED;
                    break;
                }
                ui_add_historyf(NULL, "(sent file: %s, %ld bytes)", name,
                                 file_size);
                msglog_append("you",
                    "(sent a file - see docs/PROTOCOL.md FILE type)");
            }
            continue;
        }

        {
            uint32_t sent_seq;
            if (session_send(&ctx, SL_MSG_TEXT_MESSAGE,
                              (const uint8_t *)line, (uint32_t)len,
                              &sent_seq) != 0) {
                /* Queue it for automatic resend on the next successful
                 * session, rather than losing it - a real reliability
                 * improvement over just failing silently. */
                outbox_enqueue(line);
                result = SESSION_DISCONNECTED;
                break;
            }
            track_pending_ack(&ctx, sent_seq, line);
            msglog_append("you", line);
        }

        /* Echo the user's own sent message into the history. ncurses
         * runs in noecho() mode and clears the input line once
         * submitted (ui.c), so without this the user would have no
         * on-screen record of what they just sent - unlike a plain
         * terminal, which echoes typed input on its own. */
        ui_add_history("you", line);
    }

    free(line);
    free(file_body);

    /* Unblock the receiver thread: shutdown() on the raw socket's read
     * side forces its current or next blocking wolfSSL_read() to return
     * immediately, instead of waiting up to CONN_TIMEOUT_SECONDS to
     * notice should_stop on its own. Safe to call even if the receiver
     * already ended itself (the ctx.peer_ended-break case above) -
     * shutdown() on an already-idle/half-closed socket is harmless. */
    ctx.should_stop = 1;
    SHUTDOWN_READ(sock);

    pthread_join(rtid, NULL);
    pthread_mutex_destroy(&ctx.send_mutex);
    wolfSSL_free(ctx.ssl_write);

    return result;
}

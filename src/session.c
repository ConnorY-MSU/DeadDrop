#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "session.h"
#include "message.h"
#include "hw_expansion.h"
#include "hw_oled.h"
#include "hw_tts.h"
#include "ui.h"

/* Platform bits this file needs beyond what session.h already brought in
 * (socket_t, winsock2.h on Windows). Kept local rather than folded into
 * session.h - session.h's callers don't need to know shutdown()
 * semantics, only this implementation does, same "platform knowledge
 * lives only where it's used" precedent client.c/server.c already set. */
#ifdef _WIN32
    #define SHUTDOWN_READ(s) shutdown((s), SD_RECEIVE)
#else
    #include <sys/socket.h>
    #include <unistd.h>
    #define SHUTDOWN_READ(s) shutdown((s), SHUT_RD)
#endif

/* How often the sender loop wakes up (if nothing's been typed) to
 * re-check whether the receiver thread has ended the session. Bounds the
 * worst-case delay between "peer disconnected" and this side noticing
 * and returning, when the local user hasn't typed anything. Also bounds
 * (on the real ncurses UI path) how long an incoming message's display
 * can be delayed by a concurrent ui_poll_line() wait - see ui.c's
 * ui_mutex comment. 200ms: responsive enough that neither delay is
 * perceptible, without busy-looping. */
#define STDIN_POLL_MS 200

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

/* --- Shared state between the two threads ----------------------------
 *
 * See session.h's design comment for the full reasoning on why sends
 * need a mutex around the whole serialize+write pair while parses need
 * none at all.
 */
typedef struct {
    sl_session_state *state;
    WOLFSSL *ssl_read;   /* original object, read-only after write_dup -
                           * used only by the receiver thread */
    WOLFSSL *ssl_write;  /* write_dup()'d object - used by BOTH threads
                           * (local user sends, receiver's PONG auto-
                           * reply), protected by send_mutex */
    pthread_mutex_t send_mutex;

    volatile int peer_ended;  /* set by the receiver thread once IT
                                * decides the session is over (peer
                                * DISCONNECT, read error/close, or an
                                * invalid message) */
    volatile int should_stop; /* set by the main thread once IT decides
                                * the session is over (user quit/EOF) -
                                * documentation of intent; shutdown() on
                                * the raw socket is the actual mechanism
                                * that unblocks a receiver thread sitting
                                * in a blocking read */

    int hw_fd;   /* accepted for API symmetry with oled_fd / future use
                  * (e.g. a brief flash on message receipt) - connection-
                  * level RGB status is already owned by the caller
                  * (client.c/server.c's connect loop), not this
                  * function, so this goes unused today. */
    int oled_fd;
    const char *peer_label;
} shared_session_ctx;

/* --- Shared send helper: used by BOTH threads -------------------------
 *
 * Holds send_mutex across the ENTIRE serialize+write pair - see
 * session.h's design comment for why splitting those into two separate
 * critical sections would be a real ordering/corruption bug, not just a
 * style choice.
 */
static int session_send(shared_session_ctx *ctx, uint8_t msg_type,
                         const uint8_t *body, uint32_t body_len)
{
    uint8_t out_buf[SL_MAX_MSG_SIZE];
    int total;
    int rc;

    pthread_mutex_lock(&ctx->send_mutex);

    total = sl_serialize_message(ctx->state, msg_type, body, body_len,
                                  out_buf, sizeof(out_buf));
    if (total < 0) {
        pthread_mutex_unlock(&ctx->send_mutex);
        ui_add_historyf(NULL, "(send failed: message too large, "
                               "body_len=%u)", body_len);
        return -1;
    }

    rc = wolfSSL_write(ctx->ssl_write, out_buf, total);

    pthread_mutex_unlock(&ctx->send_mutex);

    if (rc != total) {
        int err = wolfSSL_get_error(ctx->ssl_write, rc);
        char errbuf[80];
        ui_add_historyf(NULL, "(send failed: %s)",
                         wolfSSL_ERR_error_string(err, errbuf));
        return -1;
    }
    return 0;
}

/* --- Receiver thread ---------------------------------------------------
 *
 * Runs for the whole session: always reads, parses, displays, and (for
 * PING only) auto-replies, regardless of whether the local user is
 * actively typing right now - "receiving always works, replying is
 * optional". Never blocks the sender: its wolfSSL_read() call runs on
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
        ui_add_history(NULL, "(internal error: out of memory)");
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
            ui_add_historyf(NULL, "Received an invalid message from %s "
                                   "- ending session.", ctx->peer_label);
            ctx->peer_ended = 1;
            break;
        }

        /* rs == RTHREAD_RECV_OK */
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
        } else if (msg.msg_type == SL_MSG_PING) {
            ui_add_historyf(NULL, "(ping received from %s - replying)",
                             ctx->peer_label);
            if (session_send(ctx, SL_MSG_PONG, NULL, 0) != 0) {
                ctx->peer_ended = 1;
                break;
            }
        } else if (msg.msg_type == SL_MSG_PONG) {
            ui_add_historyf(NULL, "(pong received from %s)",
                             ctx->peer_label);
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
    session_result result;

    if (sl_session_init(ssl, &state) != 0) {
        ui_add_history(NULL,
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
        ui_add_history(NULL,
            "wolfSSL_write_dup failed - this wolfSSL build may lack "
            "HAVE_WRITE_DUP / --enable-writedup");
        return SESSION_DISCONNECTED;
    }

    pthread_mutex_init(&ctx.send_mutex, NULL);
    ctx.peer_ended = 0;
    ctx.should_stop = 0;
    ctx.hw_fd = hw_fd;
    ctx.oled_fd = oled_fd;
    ctx.peer_label = peer_label;

    if (pthread_create(&rtid, NULL, receiver_thread_main, &ctx) != 0) {
        ui_add_history(NULL, "run_symmetric_session: pthread_create failed");
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
    if (line == NULL) {
        ui_add_history(NULL, "run_symmetric_session: out of memory");
        ctx.should_stop = 1;
        SHUTDOWN_READ(sock);
        pthread_join(rtid, NULL);
        pthread_mutex_destroy(&ctx.send_mutex);
        wolfSSL_free(ctx.ssl_write);
        return SESSION_DISCONNECTED;
    }

    ui_set_statusf("Connected to %s", peer_label);
    ui_add_history(NULL, "Type a message and press Enter to send "
                          "('quit' to exit). Incoming messages display "
                          "automatically at any time.");

    for (;;) {
        size_t len;
        ui_poll_result pr;

        if (ctx.peer_ended) {
            ui_add_historyf(NULL, "Connection to %s lost.", peer_label);
            result = SESSION_DISCONNECTED;
            break;
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
            session_send(&ctx, SL_MSG_DISCONNECT, NULL, 0);
            result = SESSION_USER_QUIT;
            break;
        }

        /* pr == UI_POLL_LINE: line[] holds the composed, NUL-terminated
         * line (any trailing newline already stripped by ui_poll_line()). */
        len = strlen(line);

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            ui_add_history(NULL, "(you quit)");
            session_send(&ctx, SL_MSG_DISCONNECT, NULL, 0);
            result = SESSION_USER_QUIT;
            break;
        }

        if (ctx.peer_ended) {
            /* Peer ended the session while this line was being typed -
             * don't bother sending into an already-dead connection. */
            ui_add_historyf(NULL, "Connection to %s lost.", peer_label);
            result = SESSION_DISCONNECTED;
            break;
        }

        if (session_send(&ctx, SL_MSG_TEXT_MESSAGE, (const uint8_t *)line,
                          (uint32_t)len) != 0) {
            result = SESSION_DISCONNECTED;
            break;
        }

        /* Echo the user's own sent message into the history. ncurses
         * runs in noecho() mode and clears the input line once
         * submitted (ui.c), so without this the user would have no
         * on-screen record of what they just sent - unlike a plain
         * terminal, which echoes typed input on its own. */
        ui_add_history("you", line);
    }

    free(line);

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

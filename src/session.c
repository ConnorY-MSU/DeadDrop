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
#include "hw_volume.h"
#include "ui.h"
#include "outbox.h"
#include "msglog.h"

/* Platform bits beyond what session.h brought in (socket_t, winsock2.h) - shutdown() semantics are local to this .c. */
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
/* dirent.h - used by wipe_directory_contents() ("/destroy CONFIRM" below); available on both real targets, no #ifdef split needed. */
#include <dirent.h>

/* How often the sender loop wakes to re-check for a peer disconnect; also the PING/watchdog check granularity. 200ms: responsive without busy-looping. */
#define STDIN_POLL_MS 200

/* How often the sender loop sends a PING for RTT/link-quality (ui_report_rtt()); also the watchdog heartbeat interval. */
#define SESSION_PING_INTERVAL_SECONDS 10

/* Application-level watchdog for a silent peer loss (no FIN/RST) since clear_recv_timeout() disables the OS read timeout once live. Real bug found and fixed here - see COMMENT_ARCHIVE.md. */
#define SESSION_WATCHDOG_TIMEOUT_SECONDS 25

/* clear_recv_timeout - undo client.c/server.c's pre-handshake SO_RCVTIMEO once a session is live so an idle chat doesn't spuriously disconnect; 0 = block indefinitely. */
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

/* monotonic_now - clock_gettime(CLOCK_MONOTONIC) as a struct timespec, used for PING interval checks and RTT measurement. */
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

/* --- Shared state between the two threads --- */
/* See session.h: sends need a mutex around the whole serialize+write pair; parses need none. */
#define SESSION_PENDING_ACK_MAX 8      /* how many recently-sent TEXT_MESSAGEs we track for ACKs - bounded circular buffer, eviction just drops delivery-indicator tracking */
#define SESSION_ACK_PREVIEW_LEN 48

typedef struct {
    uint32_t seq_num;
    char     preview[SESSION_ACK_PREVIEW_LEN];
    int      active;
} pending_ack_entry;

typedef struct {
    dd_session_state *state;
    WOLFSSL *ssl_read;   /* original object, read-only after write_dup - used only by the receiver thread */
    WOLFSSL *ssl_write;  /* write_dup()'d object - used by BOTH threads, protected by send_mutex */
    pthread_mutex_t send_mutex;

    /* Also protected by send_mutex (reused rather than a second lock) - see session_send() and the helpers below. */
    pending_ack_entry pending_acks[SESSION_PENDING_ACK_MAX];
    int pending_ack_next_slot;
    int ping_outstanding;
    struct timespec ping_sent_at;

    volatile int peer_ended;  /* set by the receiver thread once the session is over (DISCONNECT, read error/close, or invalid message) */
    volatile long last_recv_epoch; /* time(NULL) of last message received - see SESSION_WATCHDOG_TIMEOUT_SECONDS; lockless liveness heuristic */
    volatile int should_stop; /* set once the main thread decides the session is over; unblock mechanism is shutdown() on the raw socket */

    int hw_fd;   /* RGB status owned by the caller (client.c/server.c) - used here only for the message-pending flash */
    int oled_fd;
    const char *peer_label;
    const char *self_label; /* this device's own capitalized name (inferred from peer_label); used instead of a "you" sentinel so persisted history shows the real name */
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

/* --- Shared send helper: used by BOTH threads --- */
/* Holds send_mutex across the ENTIRE serialize+write pair - splitting into two critical sections would be a real ordering bug, see session.h. out_seq_num (may be NULL): filled with the seq_num actually used - race-free, used by track_pending_ack(). */
static int session_send(shared_session_ctx *ctx, uint8_t msg_type,
                         const uint8_t *body, uint32_t body_len,
                         uint32_t *out_seq_num)
{
    uint8_t out_buf[DD_MAX_MSG_SIZE];
    int total;
    int rc;
    uint32_t used_seq_num;

    pthread_mutex_lock(&ctx->send_mutex);

    used_seq_num = ctx->state->next_seq_num; /* captured BEFORE serialize consumes it, still under the lock - race-free */

    total = dd_serialize_message(ctx->state, msg_type, body, body_len,
                                  out_buf, sizeof(out_buf));
    if (total < 0) {
        pthread_mutex_unlock(&ctx->send_mutex);
        ui_add_errorf("(send failed: message too large, "
                       "body_len=%u)", body_len);
        return -1;
    }

    rc = wolfSSL_write(ctx->ssl_write, out_buf, total);

    /* Record the outstanding PING's send time while still holding the lock - check_and_clear_ping() takes the same lock, no race. */
    if (msg_type == DD_MSG_PING && rc == total) {
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

/* track_pending_ack - remember a just-sent TEXT_MESSAGE's seq_num/preview so a later ACK can show "(delivered: "...")" - circular buffer, see SESSION_PENDING_ACK_MAX. */
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

/* consume_pending_ack - look up and consume a pending entry for seq_num; returns 1 and fills out_preview if found, 0 otherwise (eviction or untracked ACK). */
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

/* check_and_clear_ping - if a PING is outstanding, compute elapsed time, clear the flag, and return 1 with *out_rtt_ms filled in; 0 if none outstanding. */
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

/* Same directory the PIN hash and message log use ($HOME/.deaddrop/) - rides the same persisted bind mount, see msglog.c. */
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
    if ((size_t)snprintf(buf, buf_size, "%s/.deaddrop/received", home)
            >= buf_size) {
        return -1;
    }
    return 0;
}

static void ensure_dir_exists(const char *dir)
{
    /* MKDIR failing on an already-existing directory is fine/expected - not checked, matching lock.c/msglog.c precedent. */
    MKDIR(dir);
}

/* sanitize_basename - strip directory components from a wire-received filename and refuse "."/".." to prevent path traversal; falls back to a generic name. */
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

/* --- "/destroy CONFIRM" emergency-wipe protocol --- */
/* Wipes ALL local chat state on BOTH devices (even /save'd messages), for device compromise/seizure; wipes locally then sends/queues DD_MSG_DESTROY - see OUTBOX_DESTROY_SENTINEL and receiver_thread_main()'s DD_MSG_DESTROY case. */

/* Deletes every regular file directly inside `dir` (no recursion); silently no-ops if `dir` doesn't exist. */
static void wipe_directory_contents(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *entry;

    if (d == NULL) {
        return;
    }
    while ((entry = readdir(d)) != NULL) {
        char path[600];
        if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir,
                              entry->d_name) < sizeof(path)) {
            remove(path);
        }
    }
    closedir(d);
}

/* The actual "/destroy CONFIRM" effect - declared in session.h so ui.c's idle-input thread can also use it offline; shared by 3 call sites, no confirmation shown itself (wording differs per caller). */
void session_perform_local_destroy(void)
{
    msglog_destroy_all();
    ui_destroy_history();

    /* Cuts off any in-progress/queued spoken message immediately - kept here rather than duplicated across all "/destroy" call sites. */
    hw_tts_stop_and_clear();

    {
        char dir[512];
        if (received_files_dir(dir, sizeof(dir)) == 0) {
            wipe_directory_contents(dir);
        }
    }
}

/* OUTBOX_DESTROY_SENTINEL lives in session.h - this file's outbox-drain loop and ui.c's offline "/destroy" handling must agree on the exact same string. */

/* --- Receiver thread --- */
/* Runs for the whole session: reads/parses/displays and auto-replies (PING/TEXT_MESSAGE) regardless of local typing; never blocks the sender - reads on ssl_read, separate from ssl_write. */
typedef enum {
    RTHREAD_RECV_OK,
    RTHREAD_RECV_REJECTED,
    RTHREAD_RECV_CLOSED
} rthread_recv_status;

static rthread_recv_status receiver_recv_one(WOLFSSL *ssl_read,
                                              dd_session_state *state,
                                              uint8_t *recv_buf, size_t *have,
                                              dd_parsed_message *out_msg)
{
    for (;;) {
        size_t consumed = 0;
        dd_parse_result pr = dd_try_parse_message(state, recv_buf, *have,
                                                   out_msg, &consumed);

        if (pr == DD_PARSE_OK) {
            memmove(recv_buf, recv_buf + consumed, *have - consumed);
            *have -= consumed;
            return RTHREAD_RECV_OK;
        }
        if (pr == DD_PARSE_REJECTED) {
            if (consumed > 0) {
                memmove(recv_buf, recv_buf + consumed, *have - consumed);
                *have -= consumed;
            }
            return RTHREAD_RECV_REJECTED;
        }

        if (*have >= DD_MAX_MSG_SIZE) {
            return RTHREAD_RECV_REJECTED;
        }

        {
            int n = wolfSSL_read(ssl_read, (char *)(recv_buf + *have),
                                  (int)(DD_MAX_MSG_SIZE - *have));
            if (n <= 0) {
                /* Covers both a real peer-side close/error and the deliberate local shutdown(sock, SHUT_RD) on local quit. */
                return RTHREAD_RECV_CLOSED;
            }
            *have += (size_t)n;
        }
    }
}

static void *receiver_thread_main(void *arg)
{
    shared_session_ctx *ctx = (shared_session_ctx *)arg;
    uint8_t *recv_buf = malloc(DD_MAX_MSG_SIZE);
    /* Full-length NUL-terminated copy of a TEXT_MESSAGE body for ui_add_history()/ui_add_historyf() - separate from the short OLED/TTS preview[] below. */
    char *text_buf = malloc(DD_MAX_BODY_LEN + 1);
    size_t have = 0;

    if (recv_buf == NULL || text_buf == NULL) {
        free(recv_buf);
        free(text_buf);
        ui_add_error("(internal error: out of memory)");
        ctx->peer_ended = 1;
        return NULL;
    }

    for (;;) {
        dd_parsed_message msg;
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

        /* rs == RTHREAD_RECV_OK - the only place last_recv_epoch gets updated, see SESSION_WATCHDOG_TIMEOUT_SECONDS. */
        ctx->last_recv_epoch = (long)time(NULL);

        if (msg.msg_type == DD_MSG_TEXT_MESSAGE) {
            /* msg.body is length-prefixed per PROTOCOL.md, not NUL-terminated, so a NUL-terminated copy is made first; text_buf is the full message, preview[] below is shorter for OLED/speech. */
            {
                size_t n = msg.body_len;
                if (n > DD_MAX_BODY_LEN) {
                    n = DD_MAX_BODY_LEN; /* defensive; the protocol layer already enforces this cap */
                }
                memcpy(text_buf, msg.body, n);
                text_buf[n] = '\0';
            }
            ui_add_history(ctx->peer_label, text_buf);
            ui_notify_message_pending(ctx->hw_fd);
            msglog_append(ctx->peer_label, text_buf);

            /* Automatic delivery acknowledgment - see PROTOCOL.md's ACK entry; fatal on failure, like the PING->PONG reply below. */
            {
                uint8_t ack_body[4];
                seq_num_to_be(msg.seq_num, ack_body);
                if (session_send(ctx, DD_MSG_ACK, ack_body,
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
                    /* OLED only has room for ~21 chars/line - preview[] stays scoped to that use. */
                    hw_oled_draw_text(ctx->oled_fd, 1, preview);
                    hw_oled_display(ctx->oled_fd);
                }
                /* Speak the FULL message (text_buf), not the OLED-sized preview[] - hw_tts_speak() does its own truncation for speech. */
                hw_tts_speak(text_buf);
            }
        } else if (msg.msg_type == DD_MSG_ACK) {
            if (msg.body_len == 4) {
                uint32_t acked_seq = be_to_seq_num(msg.body);
                char preview[SESSION_ACK_PREVIEW_LEN];
                if (consume_pending_ack(ctx, acked_seq, preview,
                                         sizeof(preview))) {
                    ui_add_historyf(NULL, "(delivered: \"%s\")", preview);
                }
                /* Not found: normal (eviction or untracked ACK) - silently ignored, not an error. */
            }
        } else if (msg.msg_type == DD_MSG_FILE) {
            if (msg.body_len < DD_FILE_NAME_LEN_SIZE) {
                /* Malformed - too short for the length prefix (HMAC already validated, so a peer bug, not tampering); ignore, don't tear down the session. */
            } else {
                uint16_t name_len = (uint16_t)((msg.body[0] << 8) |
                                                 msg.body[1]);
                if (name_len > DD_FILE_NAME_MAX ||
                    (size_t)(DD_FILE_NAME_LEN_SIZE + name_len) >
                        msg.body_len) {
                    /* Malformed - name_len claims more than the body holds; same "ignore" handling as above. */
                } else {
                    char raw_name[DD_FILE_NAME_MAX + 1];
                    char safe_name[DD_FILE_NAME_MAX + 1];
                    const uint8_t *data = msg.body + DD_FILE_NAME_LEN_SIZE +
                                            name_len;
                    size_t data_len = msg.body_len -
                        (DD_FILE_NAME_LEN_SIZE + name_len);
                    char dir[512];
                    char path[768];

                    memcpy(raw_name, msg.body + DD_FILE_NAME_LEN_SIZE,
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
#ifndef _WIN32
                                /* Attacker-influenceable content shouldn't rely on ambient umask - explicit chmod(0600), matching lock.c/msglog.c precedent. See COMMENT_ARCHIVE.md. */
                                chmod(path, 0600);
#endif
                                if (written == data_len) {
                                    ui_add_historyf(ctx->peer_label,
                                        "sent a file: %s (%u bytes) -> "
                                        "saved to ~/.deaddrop/received/",
                                        safe_name, (unsigned)data_len);
                                    msglog_append(ctx->peer_label,
                                        "(sent a file - see "
                                        "~/.deaddrop/received/)");
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
        } else if (msg.msg_type == DD_MSG_PING) {
            /* No history notice - PING is a routine ~10s background event; fatal on failure, like ACK's send above. */
            if (session_send(ctx, DD_MSG_PONG, NULL, 0, NULL) != 0) {
                ctx->peer_ended = 1;
                break;
            }
        } else if (msg.msg_type == DD_MSG_PONG) {
            /* Also no history notice - live RTT/link-quality reading, reported to the OLED metrics section (ui_report_rtt()), not the chat log. */
            double rtt_ms;
            if (check_and_clear_ping(ctx, &rtt_ms)) {
                ui_report_rtt((int)rtt_ms);
            }
        } else if (msg.msg_type == DD_MSG_DISCONNECT) {
            ui_add_historyf(NULL, "%s sent DISCONNECT.", ctx->peer_label);
            ctx->peer_ended = 1;
            break;
        } else if (msg.msg_type == DD_MSG_DESTROY) {
            /* The peer triggered "/destroy CONFIRM" remotely; no extra auth needed - it rode in over an already authenticated, replay-protected session. */
            session_perform_local_destroy();
            ui_add_error("EMERGENCY DESTROY: the peer remotely wiped all "
                          "chat data on this device.");
        }
        /* Any other well-formed-but-unrecognized msg_type: treated as forward-compat noise, not fatal - version/HMAC/seq_num already validated. */
    }

    free(recv_buf);
    free(text_buf);
    return NULL;
}

/* --- Public entry point ------------------------------------------------ */

session_result run_symmetric_session(WOLFSSL *ssl, socket_t sock, int hw_fd,
                                      int oled_fd, const char *peer_label)
{
    dd_session_state state;
    shared_session_ctx ctx;
    pthread_t rtid;
    char *line;
    char *file_body; /* scratch buffer for building an outgoing DD_MSG_FILE body ("/send <path>") - separate from `line`, the typed command text */
    struct timespec last_ping_sent;
    session_result result;

    if (dd_session_init(ssl, &state) != 0) {
        ui_add_error(
            "dd_session_init failed - wolfSSL_export_keying_material "
            "unavailable? (needs HAVE_KEYING_MATERIAL / "
            "--enable-keying-material)");
        return SESSION_DISCONNECTED;
    }

    /* See session.h: must happen before the receiver thread starts blocking in wolfSSL_read(), or it could hit the old pre-handshake timeout. */
    clear_recv_timeout(sock);

    ctx.state = &state;
    ctx.ssl_read = ssl;

    /* wolfSSL_write_dup() turns `ssl` into a read-only object and hands back a separate write-only object - the mechanism making concurrent read/write safe. Needs HAVE_WRITE_DUP, see docs/BUILD.md. */
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
    /* Starts "now," not 0 - see SESSION_WATCHDOG_TIMEOUT_SECONDS, or a fresh session could spuriously look silent since epoch 0. */
    ctx.last_recv_epoch = (long)time(NULL);
    ctx.hw_fd = hw_fd;
    ctx.oled_fd = oled_fd;
    ctx.peer_label = peer_label;
    /* See self_label's declaration comment above: inferred from peer_label the same way ui.c's g_self_is_alpha is. */
    ctx.self_label = (peer_label != NULL && strcmp(peer_label, "Bravo") == 0)
                          ? "Alpha" : "Bravo";

    if (pthread_create(&rtid, NULL, receiver_thread_main, &ctx) != 0) {
        ui_add_error("run_symmetric_session: pthread_create failed");
        pthread_mutex_destroy(&ctx.send_mutex);
        wolfSSL_free(ctx.ssl_write);
        return SESSION_DISCONNECTED;
    }

    /* Heap-allocated rather than a stack buffer - this frame already holds shared_session_ctx/dd_session_state, so a 64KB fixed buffer would add stack pressure. */
    line = malloc(DD_MAX_BODY_LEN);
    file_body = malloc(DD_MAX_BODY_LEN);
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
    /* No per-connection instructional hint here anymore - used to spam a flaky link on every reconnect; now shown once at boot and via "/help". */

    /* Drain anything queued while offline (see outbox.h), same send/ack-tracking/persistence/history-echo treatment as a live message; runs once at session start. */
    {
        char queued[OUTBOX_MSG_MAX_LEN];
        uint32_t sent_seq;
        while (outbox_try_dequeue(queued, sizeof(queued))) {
            /* A queued "/destroy CONFIRM" from earlier - the local wipe already happened when typed; only the peer notification is left. */
            if (strcmp(queued, OUTBOX_DESTROY_SENTINEL) == 0) {
                if (session_send(&ctx, DD_MSG_DESTROY, NULL, 0, NULL) == 0) {
                    ui_add_error("EMERGENCY DESTROY: queued wipe command "
                                  "delivered to peer.");
                } else {
                    outbox_enqueue(queued);
                    break;
                }
                continue;
            }

            {
                size_t qlen = strlen(queued);
                if (session_send(&ctx, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)queued, (uint32_t)qlen,
                                  &sent_seq) == 0) {
                    track_pending_ack(&ctx, sent_seq, queued);
                    msglog_append(ctx.self_label, queued);
                    ui_add_history(ctx.self_label, queued);
                } else {
                    /* Send failed mid-drain (connection died again) - put it back and stop draining; the next session start resumes from here. */
                    outbox_enqueue(queued);
                    break;
                }
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

        /* Periodic PING for RTT/link-quality - see SESSION_PING_INTERVAL_SECONDS; skips sending a new one while a previous PING is still outstanding. */
        {
            struct timespec now_ts = monotonic_now();
            if (ms_between(last_ping_sent, now_ts) >=
                    SESSION_PING_INTERVAL_SECONDS * 1000.0) {
                int outstanding;
                pthread_mutex_lock(&ctx.send_mutex);
                outstanding = ctx.ping_outstanding;
                pthread_mutex_unlock(&ctx.send_mutex);
                if (!outstanding) {
                    session_send(&ctx, DD_MSG_PING, NULL, 0, NULL);
                }
                last_ping_sent = now_ts;
            }
        }

        /* Watchdog: end the session if nothing received in too long - see SESSION_WATCHDOG_TIMEOUT_SECONDS; SHUTDOWN_READ() unblocks the receiver, which sets peer_ended. */
        if ((long)time(NULL) - ctx.last_recv_epoch >=
                SESSION_WATCHDOG_TIMEOUT_SECONDS) {
            SHUTDOWN_READ(sock);
        }

        pr = ui_poll_line(line, DD_MAX_BODY_LEN, STDIN_POLL_MS);

        if (pr == UI_POLL_TIMEOUT) {
            continue;
        }
        if (pr == UI_POLL_QUIT) {
            /* stdin closed (EOF) - only the plain-console fallback ever returns this; treated the same as an explicit quit. */
            ui_add_history(NULL, "(you quit)");
            session_send(&ctx, DD_MSG_DISCONNECT, NULL, 0, NULL);
            result = SESSION_USER_QUIT;
            break;
        }

        /* pr == UI_POLL_LINE: line[] holds the composed, NUL-terminated line (trailing newline already stripped by ui_poll_line()). */
        len = strlen(line);

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            ui_add_history(NULL, "(you quit)");
            session_send(&ctx, DD_MSG_DISCONNECT, NULL, 0, NULL);
            result = SESSION_USER_QUIT;
            break;
        }

        /* "/clear" - purely local, never sent to the peer; checked before ctx.peer_ended. Zeroes the on-disk log and on-screen scrollback, keeping "/save"d messages. */
        if (strcmp(line, "/clear") == 0) {
            msglog_clear_except_saved();
            ui_clear_history();
            ui_add_history(NULL,
                "(chat cleared - any /save'd messages were kept)");
            continue;
        }

        /* "/help" - same purely-local reasoning as "/clear" above; re-prints the guide ui_init() shows once at boot. */
        if (strcmp(line, "/help") == 0) {
            ui_show_help();
            continue;
        }

        /* "/volume" (report) and "/volume <0-100>" (set) - an OS-level ALSA mixer setting; hw_volume_get/set() are safe no-ops on non-Linux. */
        if (strcmp(line, "/volume") == 0) {
            int pct = hw_volume_get();
            if (pct < 0) {
                ui_add_error("Could not read current volume (amixer "
                              "unavailable?).");
            } else {
                ui_add_historyf(NULL, "(volume: %d%%)", pct);
            }
            continue;
        }
        if (strncmp(line, "/volume ", 8) == 0) {
            const char *arg = line + 8;
            char *endptr = NULL;
            long pct = strtol(arg, &endptr, 10);
            if (endptr == arg || *endptr != '\0' || pct < 0 || pct > 100) {
                ui_add_error("Usage: /volume <0-100>");
            } else if (hw_volume_set((int)pct) != 0) {
                ui_add_error("Failed to set volume (amixer unavailable?).");
            } else {
                ui_add_historyf(NULL, "(volume set to %d%%)", (int)pct);
            }
            continue;
        }

        /* "/destroy" and "/destroy CONFIRM" - the emergency-wipe protocol; "/destroy" alone is inert (just a warning), checked before ctx.peer_ended like "/clear". */
        if (strcmp(line, "/destroy") == 0) {
            ui_add_error(
                "EMERGENCY DESTROY: type '/destroy CONFIRM' (exact, "
                "case-sensitive) to IRREVERSIBLY wipe ALL chat history, "
                "saved messages, and received files on BOTH this device "
                "and the paired device. This cannot be undone.");
            continue;
        }

        if (strcmp(line, "/destroy CONFIRM") == 0) {
            session_perform_local_destroy();
            ui_add_error("EMERGENCY DESTROY: all local chat data wiped.");

            /* Notify the peer so both devices end up wiped - queue it (OUTBOX_DESTROY_SENTINEL) if unreachable, like a queued TEXT_MESSAGE. */
            if (ctx.peer_ended ||
                    session_send(&ctx, DD_MSG_DESTROY, NULL, 0, NULL) != 0) {
                if (outbox_enqueue(OUTBOX_DESTROY_SENTINEL) == 0) {
                    ui_add_error(
                        "EMERGENCY DESTROY: peer unreachable right now - "
                        "the wipe command is queued and will be "
                        "delivered automatically once reconnected.");
                } else {
                    /* See ui.c's matching idle-thread comment - the outbound queue being full is rare, but must never silently fail to queue. */
                    ui_add_error(
                        "EMERGENCY DESTROY: peer unreachable AND the "
                        "outbound queue is full - peer notification "
                        "could NOT be queued. Run '/destroy CONFIRM' "
                        "again once reconnected to notify the peer.");
                }
                result = SESSION_DISCONNECTED;
                break;
            }

            ui_add_error("EMERGENCY DESTROY: peer notified and wiped.");
            continue;
        }

        if (ctx.peer_ended) {
            /* Peer ended the session while this line was being typed - queue instead of sending into a dead connection. */
            outbox_enqueue(line);
            ui_add_historyf(NULL, "Connection to %s lost. Your message "
                                   "has been queued.", peer_label);
            result = SESSION_DISCONNECTED;
            break;
        }

        /* "/save <text>" - a normal TEXT_MESSAGE logged with the "[SAVED]" marker so "/clear" keeps it; no way to retroactively mark an older message in v1. */
        if (len > 6 && strncmp(line, "/save ", 6) == 0) {
            const char *text = line + 6;
            uint32_t sent_seq;

            if (session_send(&ctx, DD_MSG_TEXT_MESSAGE,
                              (const uint8_t *)text, (uint32_t)strlen(text),
                              &sent_seq) != 0) {
                outbox_enqueue(text); /* the SAVED tag doesn't survive an offline-queue retry - an accepted limitation */
                result = SESSION_DISCONNECTED;
                break;
            }
            track_pending_ack(&ctx, sent_seq, text);
            msglog_append_saved(ctx.self_label, text);
            ui_add_historyf(ctx.self_label, "[SAVED] %s", text);
            continue;
        }

        /* "/send <path>" - a small local file, transmitted as one DD_MSG_FILE; see PROTOCOL.md's FILE entry for the hard size cap (no chunking). */
        if (len > 6 && strncmp(line, "/send ", 6) == 0) {
            const char *filepath = line + 6;
            FILE *f = fopen(filepath, "rb");

            if (f == NULL) {
                ui_add_errorf("(/send failed: cannot open '%s')",
                               filepath);
                continue;
            }

            {
                /* Basename of the LOCAL path, sent as the filename label - reuses sanitize_basename() for consistency, though this path is trusted. */
                char name[DD_FILE_NAME_MAX + 1];
                size_t name_len;
                long file_size;
                size_t max_data;

                sanitize_basename(filepath, name, sizeof(name));
                name_len = strlen(name);

                fseek(f, 0, SEEK_END);
                file_size = ftell(f);
                fseek(f, 0, SEEK_SET);

                max_data = DD_MAX_BODY_LEN - DD_FILE_NAME_LEN_SIZE -
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
                memcpy(file_body + DD_FILE_NAME_LEN_SIZE, name, name_len);
                {
                    size_t got = fread(
                        file_body + DD_FILE_NAME_LEN_SIZE + name_len,
                        1, (size_t)file_size, f);
                    fclose(f);
                    if (got != (size_t)file_size) {
                        ui_add_errorf(
                            "(/send failed: could not fully read '%s')",
                            filepath);
                        continue;
                    }
                }

                if (session_send(&ctx, DD_MSG_FILE, (uint8_t *)file_body,
                                  (uint32_t)(DD_FILE_NAME_LEN_SIZE +
                                             name_len + (size_t)file_size),
                                  NULL) != 0) {
                    result = SESSION_DISCONNECTED;
                    break;
                }
                ui_add_historyf(NULL, "(sent file: %s, %ld bytes)", name,
                                 file_size);
                msglog_append(ctx.self_label,
                    "(sent a file - see docs/PROTOCOL.md FILE type)");
            }
            continue;
        }

        {
            uint32_t sent_seq;
            if (session_send(&ctx, DD_MSG_TEXT_MESSAGE,
                              (const uint8_t *)line, (uint32_t)len,
                              &sent_seq) != 0) {
                /* Queue it for automatic resend on the next successful session, rather than losing it. */
                outbox_enqueue(line);
                result = SESSION_DISCONNECTED;
                break;
            }
            track_pending_ack(&ctx, sent_seq, line);
            msglog_append(ctx.self_label, line);
        }

        /* Echo the user's own sent message into the history - ncurses runs in noecho() mode and clears the input line otherwise. */
        ui_add_history(ctx.self_label, line);
    }

    free(line);
    free(file_body);

    /* Unblock the receiver thread: shutdown() on the socket's read side forces its blocking wolfSSL_read() to return; harmless if already idle. */
    ctx.should_stop = 1;
    SHUTDOWN_READ(sock);

    pthread_join(rtid, NULL);
    pthread_mutex_destroy(&ctx.send_mutex);
    wolfSSL_free(ctx.ssl_write);

    return result;
}

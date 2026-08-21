#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Portability shim: this code has to run both here (Windows, dev machine)
 * and, unchanged, on the Raspberry Pi (Linux) in Week 4 - Winsock and
 * POSIX sockets differ in header, init/cleanup, socket type, error
 * sentinels, close call, and how a socket-option timeout is expressed.
 * Everything below this block is the only place that knowledge lives;
 * the rest of the file uses the portable names on the right. */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define SOCKET_INVALID INVALID_SOCKET
    #define SOCKET_ERR_RET SOCKET_ERROR
    #define CLOSE_SOCKET closesocket
    #define SOCK_LAST_ERROR() WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int socket_t;
    #define SOCKET_INVALID (-1)
    #define SOCKET_ERR_RET (-1)
    #define CLOSE_SOCKET close
    #define SOCK_LAST_ERROR() errno
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "revocation.h"
#include "message.h"
#include "hw_expansion.h"
#include "hw_oled.h"
#include "hw_tts.h"

#define SERVER_PORT 4433
#define LISTEN_BACKLOG 1

#define SERIAL_BUF_SIZE 32

/* How long a single connection is allowed to sit idle mid-handshake or
 * mid-read before we give up on it. Without this, a stalled or malicious
 * peer that opens a TCP connection and never completes the handshake (or
 * completes it and then never sends anything) blocks this server - which
 * handles exactly one connection at a time - from accepting anyone else,
 * including the legitimate peer's own reconnect attempt. 30s is generous
 * for a real handshake/read on a slow mobile network, short enough that a
 * stalled connection doesn't lock everyone else out for long. It also
 * doubles as the mechanism that eventually notices a peer whose network
 * simply vanished (no FIN/RST ever arrives) rather than blocking forever -
 * see client.c's reconnect loop, which depends on reads eventually erroring
 * out instead of hanging indefinitely. */
#define CONN_TIMEOUT_SECONDS 30

static void set_socket_timeout(socket_t s)
{
#ifdef _WIN32
    DWORD timeout_ms = CONN_TIMEOUT_SECONDS * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = CONN_TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

/* ASSUMPTION: this project's PKI is single-level - the CA signs each
 * device's leaf certificate directly, with no intermediate CAs (see
 * docs/PKI_SETUP.md). wolfSSL_X509_STORE_CTX_get_current_cert() returns
 * whichever certificate is currently being verified, which is only
 * guaranteed to be the leaf when the chain has exactly one certificate
 * in it. If an intermediate CA is ever introduced, this callback would
 * need to explicitly walk to the leaf (e.g. via depth 0) rather than
 * trusting "current cert" to mean "the peer's own cert" - untested,
 * revisit before adding any intermediate CA to this project's PKI. */
static int my_verify_callback(int preverify_ok, WOLFSSL_X509_STORE_CTX *store)
{
    WOLFSSL_X509 *cert;
    byte serial_bytes[SERIAL_BUF_SIZE];
    int serial_len = sizeof(serial_bytes);
    char serial_hex[SERIAL_BUF_SIZE * 2 + 1];
    int i;
    int rc;

    if (!preverify_ok) {
        fprintf(stderr,
            "Verify callback: standard cert-chain verification failed.\n");
        return 0;
    }

    cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if (cert == NULL) {
        fprintf(stderr, "Verify callback: no current cert available.\n");
        return 0;
    }

    rc = wolfSSL_X509_get_serial_number(cert, serial_bytes, &serial_len);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Verify callback: could not read serial number.\n");
        return 0;
    }

    if (serial_len <= 0 || (size_t)(serial_len * 2) >= sizeof(serial_hex)) {
        fprintf(stderr, "Verify callback: unexpected serial length (%d).\n",
                serial_len);
        return 0;
    }

    for (i = 0; i < serial_len; i++) {
        sprintf(&serial_hex[i * 2], "%02X", serial_bytes[i]);
    }
    serial_hex[serial_len * 2] = '\0';

    printf("Verify callback: checking serial %s against revocation list.\n",
           serial_hex);
    fflush(stdout);

    if (revocation_is_revoked(serial_hex)) {
        fprintf(stderr, "Verify callback: serial %s is REVOKED - rejecting.\n",
                serial_hex);
        return 0;
    }

    printf("Verify callback: serial %s not revoked, proceeding.\n", serial_hex);
    fflush(stdout);
    return 1;
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <server_cert.pem> -k <server_key.pem> "
        "-A <ca_cert.pem> -r <revoked_serials.txt>\n"
        "All four arguments are required - there are no default paths,\n"
        "since a hardcoded path baked into the binary would tie it to one\n"
        "machine and break the moment this runs on a different device.\n",
        prog_name);
}

static void parse_args(int argc, char *argv[],
                        const char **cert_path, const char **key_path,
                        const char **ca_path, const char **revoked_path)
{
    int i;
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            *cert_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            *key_path = argv[++i];
        } else if (strcmp(argv[i], "-A") == 0) {
            *ca_path = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0) {
            *revoked_path = argv[++i];
        }
    }
}

static const char *msg_type_name(uint8_t t)
{
    switch (t) {
        case SL_MSG_TEXT_MESSAGE: return "TEXT_MESSAGE";
        case SL_MSG_PING:         return "PING";
        case SL_MSG_PONG:         return "PONG";
        case SL_MSG_DISCONNECT:   return "DISCONNECT";
        default:                  return "UNKNOWN";
    }
}

typedef enum {
    RECV_OK,        /* out_msg holds one fully validated message */
    RECV_REJECTED,  /* a framed message arrived but failed validation */
    RECV_CLOSED     /* peer closed, a read error occurred, or timeout */
} recv_status;

/*
 * receive_one_message - block until exactly one complete message has
 * been read off ssl and parsed (or the connection fails). Handles the
 * case where a single wolfSSL_read() returns bytes belonging to more
 * than one message: leftover bytes are kept in recv_buf/have across
 * calls, and re-checked for another complete message before going back
 * to wolfSSL_read() again.
 *
 * recv_buf must be at least SL_MAX_MSG_SIZE bytes. *have is the caller's
 * persistent "how many valid bytes are currently in recv_buf" cursor -
 * initialize to 0 before the first call for a given connection and don't
 * touch it between calls.
 */
static recv_status receive_one_message(WOLFSSL *ssl, sl_session_state *state,
                                        uint8_t *recv_buf, size_t *have,
                                        sl_parsed_message *out_msg)
{
    for (;;) {
        /* First, see if a complete message is already sitting in the
         * buffer from a previous read (this is the "two messages in one
         * read()" case). */
        size_t consumed = 0;
        sl_parse_result pr = sl_try_parse_message(state, recv_buf, *have,
                                                   out_msg, &consumed);

        if (pr == SL_PARSE_OK) {
            memmove(recv_buf, recv_buf + consumed, *have - consumed);
            *have -= consumed;
            return RECV_OK;
        }
        if (pr == SL_PARSE_REJECTED) {
            /* consumed may be 0 (implausible body_length - no safe
             * resync point) or >0 (a well-framed but invalid message).
             * Either way we treat rejection as fatal for this connection
             * rather than trying to resynchronize on a stream we can no
             * longer fully trust. */
            if (consumed > 0) {
                memmove(recv_buf, recv_buf + consumed, *have - consumed);
                *have -= consumed;
            }
            return RECV_REJECTED;
        }

        /* SL_PARSE_INCOMPLETE: need more bytes. */
        if (*have >= SL_MAX_MSG_SIZE) {
            /* Buffer is completely full and still not a complete valid
             * message - can't happen for a well-formed sender (body_length
             * is capped, and the buffer is sized for the max possible
             * message), so this means something is wrong upstream.
             * Treat as fatal, same as any other rejection. */
            return RECV_REJECTED;
        }

        {
            int n = wolfSSL_read(ssl, (char *)(recv_buf + *have),
                                  (int)(SL_MAX_MSG_SIZE - *have));
            if (n <= 0) {
                int err = wolfSSL_get_error(ssl, n);
                char errbuf[80];
                fprintf(stderr, "wolfSSL_read: %s\n",
                        wolfSSL_ERR_error_string(err, errbuf));
                return RECV_CLOSED;
            }
            *have += (size_t)n;
        }
    }
}

static int send_message(WOLFSSL *ssl, sl_session_state *state,
                         uint8_t msg_type, const uint8_t *body,
                         uint32_t body_len)
{
    uint8_t out_buf[SL_MAX_MSG_SIZE];
    int total;
    int rc;

    total = sl_serialize_message(state, msg_type, body, body_len,
                                  out_buf, sizeof(out_buf));
    if (total < 0) {
        fprintf(stderr, "send_message: sl_serialize_message failed "
                         "(body_len=%u)\n", body_len);
        return -1;
    }

    rc = wolfSSL_write(ssl, out_buf, total);
    if (rc != total) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr, "wolfSSL_write: %s\n",
                wolfSSL_ERR_error_string(err, errbuf));
        return -1;
    }
    return 0;
}

/* Handle one already-mTLS-authenticated connection end to end: derive the
 * session's HMAC key, then loop receiving/validating/replying to framed
 * messages until the peer sends DISCONNECT, the connection drops, or an
 * invalid message is received. oled_fd is passed in (rather than opened
 * here) for the same reason hw_fd is in main() - it's a physical device
 * with its own lifecycle independent of any one connection. */
static void handle_connection(WOLFSSL *ssl, int oled_fd)
{
    sl_session_state state;
    uint8_t *recv_buf;
    size_t have = 0;

    if (sl_session_init(ssl, &state) != 0) {
        fprintf(stderr,
            "sl_session_init failed - wolfSSL_export_keying_material "
            "unavailable? (needs HAVE_KEYING_MATERIAL / "
            "--enable-keying-material - see docs/BUILD.md)\n");
        return;
    }

    recv_buf = malloc(SL_MAX_MSG_SIZE);
    if (recv_buf == NULL) {
        fprintf(stderr, "handle_connection: out of memory\n");
        return;
    }

    for (;;) {
        sl_parsed_message msg;
        recv_status rs = receive_one_message(ssl, &state, recv_buf, &have,
                                              &msg);

        if (rs == RECV_CLOSED) {
            printf("Connection closed.\n");
            break;
        }
        if (rs == RECV_REJECTED) {
            fprintf(stderr,
                "Rejected an invalid message - closing connection.\n");
            break;
        }

        /* rs == RECV_OK */
        printf("Received %s (seq=%u, %u bytes)\n",
               msg_type_name(msg.msg_type), msg.seq_num, msg.body_len);
        /* stdout is fully block-buffered here (redirected to a file/pipe,
         * not a TTY), so without an explicit flush this can sit invisible
         * in the buffer indefinitely once the process goes back to
         * blocking in accept() for the next connection - which looks
         * identical, from the outside, to the process having hung. Bit
         * me for real while testing DISCONNECT delivery: the message had
         * actually arrived and been processed correctly the whole time,
         * this line just hadn't been flushed to where I could see it. */
        fflush(stdout);

        if (msg.msg_type == SL_MSG_TEXT_MESSAGE) {
            printf("Client message: %.*s\n", (int)msg.body_len, msg.body);
            fflush(stdout);

            /* Case OLED + TTS notification (no-op on non-Linux / hardware-
             * absent, see hw_oled.h/hw_tts.h). msg.body is length-prefixed
             * per PROTOCOL.md, NOT a NUL-terminated C string - both
             * hw_oled_draw_text() (expects a real C string) and
             * hw_tts_speak() (same) need a bounded, NUL-terminated copy
             * made first; passing msg.body directly to either would read
             * past msg.body_len looking for a terminator that isn't
             * necessarily there. Bounded to a small preview length - the
             * OLED line is 21 characters wide, and speaking a full 64KB
             * message aloud would be its own bad idea regardless of what
             * hw_tts_speak()'s own internal cap does. */
            {
                char preview[64];
                size_t preview_len = msg.body_len;
                if (preview_len > sizeof(preview) - 1) {
                    preview_len = sizeof(preview) - 1;
                }
                memcpy(preview, msg.body, preview_len);
                preview[preview_len] = '\0';

                hw_oled_draw_text(oled_fd, 0, "New message:");
                hw_oled_draw_text(oled_fd, 1, preview);
                hw_oled_display(oled_fd);

                hw_tts_speak(preview);
            }

            {
                /* "ack: " + original text, echoed back so the exchange is
                 * visible on both ends. reply[] is sized for the worst
                 * case (prefix + a full max-length body) so snprintf
                 * itself never truncates - but the PROTOCOL.md body_length
                 * cap (SL_MAX_BODY_LEN) is a separate, smaller limit than
                 * this buffer's size, and a client message at or near that
                 * cap would make "ack: " + body exceed it. Cap reply_len
                 * to SL_MAX_BODY_LEN explicitly so this can never produce
                 * a message sl_serialize_message() would refuse to send -
                 * a message this close to the cap is already an edge case
                 * on the sender's part, so truncating the echoed tail is
                 * an acceptable, deliberate tradeoff versus dropping the
                 * whole reply (and the connection) over it. */
                char reply[7 + SL_MAX_BODY_LEN];
                int reply_len = snprintf(reply, sizeof(reply), "ack: %.*s",
                                          (int)msg.body_len, msg.body);
                if (reply_len < 0) {
                    reply_len = 0;
                }
                if ((size_t)reply_len > sizeof(reply) - 1) {
                    reply_len = (int)sizeof(reply) - 1;
                }
                if ((uint32_t)reply_len > SL_MAX_BODY_LEN) {
                    reply_len = (int)SL_MAX_BODY_LEN;
                }
                if (send_message(ssl, &state, SL_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)reply,
                                  (uint32_t)reply_len) != 0) {
                    break;
                }
            }
        } else if (msg.msg_type == SL_MSG_PING) {
            printf("Ping received - replying with PONG.\n");
            fflush(stdout);
            if (send_message(ssl, &state, SL_MSG_PONG, NULL, 0) != 0) {
                break;
            }
        } else if (msg.msg_type == SL_MSG_PONG) {
            printf("Pong received.\n");
            fflush(stdout);
        } else if (msg.msg_type == SL_MSG_DISCONNECT) {
            printf("Peer sent DISCONNECT - closing cleanly.\n");
            fflush(stdout);
            break;
        }
    }

    free(recv_buf);
}

int main(int argc, char *argv[])
{
    socket_t listen_sock = SOCKET_INVALID;
    struct sockaddr_in server_addr;
    WOLFSSL_CTX *ctx = NULL;
    int rc;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    const char *cert_path = NULL;
    const char *key_path = NULL;
    const char *ca_path = NULL;
    const char *revoked_path = NULL;
    int hw_fd;
    int oled_fd;

    parse_args(argc, argv, &cert_path, &key_path, &ca_path, &revoked_path);

    if (cert_path == NULL || key_path == NULL || ca_path == NULL ||
        revoked_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    rc = revocation_load(revoked_path);
    if (rc != 0) {
        fprintf(stderr,
            "Warning: revocation_load(\"%s\") failed - all certs will "
            "be treated as revoked until this is fixed.\n", revoked_path);
    } else {
        printf("Loaded revoked-serials list: %s\n", revoked_path);
    }

#ifdef _WIN32
    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return 1;
    }
#endif

    /* --- wolfSSL init + context --- */
    rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed: %d\n", rc);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    rc = wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_certificate_file failed (rc=%d) for %s\n",
            rc, cert_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    rc = wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_PrivateKey_file failed (rc=%d) for %s\n",
            rc, key_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    rc = wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_load_verify_locations failed (rc=%d) for %s\n",
            rc, ca_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("wolfSSL initialized; cert/key/CA loaded from %s / %s / %s\n",
           cert_path, key_path, ca_path);
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        my_verify_callback);

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == SOCKET_INVALID) {
        fprintf(stderr, "socket() failed: %d\n", SOCK_LAST_ERROR());
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    {
        int reuse = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&reuse, sizeof(reuse));
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    rc = bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc == SOCKET_ERR_RET) {
        fprintf(stderr, "bind() failed: %d\n", SOCK_LAST_ERROR());
        CLOSE_SOCKET(listen_sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    rc = listen(listen_sock, LISTEN_BACKLOG);
    if (rc == SOCKET_ERR_RET) {
        fprintf(stderr, "listen() failed: %d\n", SOCK_LAST_ERROR());
        CLOSE_SOCKET(listen_sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("Listening on port %d...\n", SERVER_PORT);
    fflush(stdout);

    /* Case RGB status light (no-op on non-Linux / hardware-absent - see
     * hw_expansion.h). See client.c's matching comment for why this is
     * opened once here rather than per-connection, and why MANUAL_RGB
     * mode has to be set before a color write has any visible effect. */
    hw_fd = hw_expansion_open();
    hw_expansion_set_led_mode(hw_fd, HW_LED_MODE_MANUAL_RGB);
    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);

    /* Case OLED (no-op on non-Linux / hardware-absent - see hw_oled.h),
     * same "opened once, lives for the whole process" reasoning as the
     * RGB light above. Shows a simple idle message rather than a blank
     * screen, so it's obvious at a glance the service is actually
     * running, not just that the screen happens to be off. */
    oled_fd = hw_oled_open();
    hw_oled_draw_text(oled_fd, 0, "SecureLink server");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

    for (;;) {
        socket_t client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == SOCKET_INVALID) {
            fprintf(stderr, "accept() failed: %d\n", SOCK_LAST_ERROR());
            continue;
        }
        printf("Raw TCP client connected.\n");
        fflush(stdout);

        /* See CONN_TIMEOUT_SECONDS above: bounds how long a single stalled
         * or malicious connection can block every other connection,
         * including the legitimate peer's own reconnect attempt. */
        set_socket_timeout(client_sock);

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failed\n");
            CLOSE_SOCKET(client_sock);
            continue;
        }

        wolfSSL_set_fd(ssl, (int)client_sock);

        /* See client.c's matching comment: wolfSSL frees its handshake
         * arrays once the handshake completes, but handle_connection()
         * needs them afterward (via sl_session_init() in message.c) to
         * derive the per-session HMAC key. Must be called before
         * wolfSSL_accept(). */
        wolfSSL_KeepArrays(ssl);

        rc = wolfSSL_accept(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, rc);
            char errbuf[80];
            fprintf(stderr, "Handshake failed: %s\n",
                    wolfSSL_ERR_error_string(err, errbuf));
        } else {
            printf("mTLS handshake succeeded.\n");
            fflush(stdout);
            hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTED);
            hw_oled_draw_text(oled_fd, 0, "SecureLink server");
            hw_oled_draw_text(oled_fd, 1, "Connected");
            hw_oled_display(oled_fd);
            handle_connection(ssl, oled_fd);
            hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
            hw_oled_draw_text(oled_fd, 0, "SecureLink server");
            hw_oled_draw_text(oled_fd, 1, "Waiting...");
            hw_oled_display(oled_fd);

            /* See client.c's matching comment: a graceful close_notify
             * here (rather than abruptly freeing/closing) avoids Winsock
             * sending a hard RST when there's unread data still sitting
             * in this socket's receive buffer, which could otherwise
             * abort delivery of whatever this server just sent (e.g. an
             * ack) before the client ever sees it. Best-effort, doesn't
             * block waiting for the client's own close_notify in return. */
            wolfSSL_shutdown(ssl);
        }

        wolfSSL_free(ssl);
        CLOSE_SOCKET(client_sock);
    }

    /* KNOWN GAP, not yet fixed: the loop above never breaks, so
     * everything from here down is currently unreachable. Neither this
     * process nor systemd's default `systemctl stop` (which sends
     * SIGTERM) installs a signal handler, so today a stop/restart is an
     * abrupt kill, not a graceful shutdown through this cleanup path.
     * Fixing this properly needs a signal handler whose exact shape
     * differs by platform (POSIX signal()/sigaction() vs Windows
     * SetConsoleCtrlHandler(), and a blocking accept() needs to actually
     * be interrupted, not just have a flag checked around it) - left
     * unimplemented here rather than guessed at and left unverified on
     * a platform this can't currently be tested on. Revisit in Week 4
     * once this is building and running natively on the Pi. */
    CLOSE_SOCKET(listen_sock);
    hw_expansion_close(hw_fd);
    hw_oled_close(oled_fd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    revocation_free();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
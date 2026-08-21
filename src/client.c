#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Portability shim - see the matching block in server.c for why this
 * exists: this code runs both here (Windows) and, unchanged, on the
 * Raspberry Pi (Linux) in Week 4. */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define SOCKET_INVALID INVALID_SOCKET
    #define SOCKET_ERR_RET SOCKET_ERROR
    #define CLOSE_SOCKET closesocket
    #define SOCK_LAST_ERROR() WSAGetLastError()
    #define SLEEP_SECONDS(s) Sleep((s) * 1000)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int socket_t;
    #define SOCKET_INVALID (-1)
    #define SOCKET_ERR_RET (-1)
    #define CLOSE_SOCKET close
    #define SOCK_LAST_ERROR() errno
    #define SLEEP_SECONDS(s) sleep(s)
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "message.h"

/* Host/port are generic, sensible defaults (loopback, this project's
 * standard port) - not tied to any one machine, so they're fine to keep
 * as defaults. Cert/key/CA paths are NOT: a hardcoded absolute path
 * only ever works on the machine it was typed on, so those are required
 * arguments with no default, same reasoning as server.c. */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433

/* Same timeout server.c applies to its side of each connection - without
 * this, a network that silently vanishes (no FIN/RST) would leave
 * wolfSSL_read() blocked forever instead of eventually erroring out,
 * which is what the reconnect loop below depends on to ever notice a
 * dead connection. */
#define CONN_TIMEOUT_SECONDS 30

/* Reconnect backoff: start at 1s, double on each consecutive failure,
 * cap at 30s so we're not waiting forever between retries but also not
 * hammering a server (or network) that's still down. */
#define RECONNECT_INITIAL_DELAY_SECONDS 1
#define RECONNECT_MAX_DELAY_SECONDS 30

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

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <client_cert.pem> -k <client_key.pem> "
        "-A <ca_cert.pem> [-h <host>] [-p <port>]\n"
        "-c/-k/-A are required - there are no default paths, since a\n"
        "hardcoded path baked into the binary would tie it to one machine.\n"
        "-h/-p default to %s:%d if omitted.\n",
        prog_name, DEFAULT_HOST, DEFAULT_PORT);
}

static void parse_args(int argc, char *argv[],
                        const char **host, int *port,
                        const char **cert_path, const char **key_path,
                        const char **ca_path)
{
    int i;
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            *host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0) {
            *port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0) {
            *cert_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            *key_path = argv[++i];
        } else if (strcmp(argv[i], "-A") == 0) {
            *ca_path = argv[++i];
        }
    }
}

/* --- Message framing glue: identical shape to server.c's, duplicated
 * rather than factored into a third file - see server.c's comment above
 * receive_one_message() for why that's the deliberate choice here, same
 * as the portability shim above. --- */

typedef enum {
    RECV_OK,
    RECV_REJECTED,
    RECV_CLOSED
} recv_status;

static recv_status receive_one_message(WOLFSSL *ssl, sl_session_state *state,
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
            return RECV_OK;
        }
        if (pr == SL_PARSE_REJECTED) {
            if (consumed > 0) {
                memmove(recv_buf, recv_buf + consumed, *have - consumed);
                *have -= consumed;
            }
            return RECV_REJECTED;
        }

        if (*have >= SL_MAX_MSG_SIZE) {
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

/* --- Interactive session --- */

typedef enum {
    SESSION_USER_QUIT,   /* user typed quit/exit or closed stdin (EOF) */
    SESSION_DISCONNECTED /* a send/receive failed or an invalid message
                           * arrived - caller should reconnect */
} session_result;

/*
 * run_interactive_session - prompt for a line, send it as TEXT_MESSAGE,
 * wait for the server's reply, display it, repeat. Runs until the user
 * quits or the connection fails in either direction.
 */
static session_result run_interactive_session(WOLFSSL *ssl)
{
    sl_session_state state;
    uint8_t *recv_buf;
    char line[SL_MAX_BODY_LEN];
    session_result result;

    if (sl_session_init(ssl, &state) != 0) {
        fprintf(stderr,
            "sl_session_init failed - wolfSSL_export_keying_material "
            "unavailable? (needs HAVE_KEYING_MATERIAL / "
            "--enable-keying-material - see docs/BUILD.md)\n");
        return SESSION_DISCONNECTED;
    }

    recv_buf = malloc(SL_MAX_MSG_SIZE);
    if (recv_buf == NULL) {
        fprintf(stderr, "run_interactive_session: out of memory\n");
        return SESSION_DISCONNECTED;
    }

    printf("Connected. Type a message and press Enter (or 'quit' to exit).\n");

    for (;;) {
        size_t have = 0;
        size_t len;

        printf("> ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            /* EOF on stdin (e.g. Ctrl-D / Ctrl-Z) - treat the same as
             * an explicit quit. */
            printf("\n");
            send_message(ssl, &state, SL_MSG_DISCONNECT, NULL, 0);
            result = SESSION_USER_QUIT;
            break;
        }

        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            send_message(ssl, &state, SL_MSG_DISCONNECT, NULL, 0);
            result = SESSION_USER_QUIT;
            break;
        }

        if (send_message(ssl, &state, SL_MSG_TEXT_MESSAGE,
                          (const uint8_t *)line, (uint32_t)len) != 0) {
            result = SESSION_DISCONNECTED;
            break;
        }

        {
            sl_parsed_message msg;
            recv_status rs = receive_one_message(ssl, &state, recv_buf,
                                                  &have, &msg);

            if (rs == RECV_CLOSED) {
                fprintf(stderr, "Connection lost.\n");
                result = SESSION_DISCONNECTED;
                break;
            }
            if (rs == RECV_REJECTED) {
                fprintf(stderr,
                    "Received an invalid message from server - "
                    "disconnecting.\n");
                result = SESSION_DISCONNECTED;
                break;
            }

            if (msg.msg_type == SL_MSG_TEXT_MESSAGE) {
                printf("Server: %.*s\n", (int)msg.body_len, msg.body);
            } else if (msg.msg_type == SL_MSG_PONG) {
                printf("(pong received)\n");
            } else if (msg.msg_type == SL_MSG_DISCONNECT) {
                printf("Server is disconnecting.\n");
                result = SESSION_DISCONNECTED;
                break;
            } else {
                printf("(unexpected message type 0x%02x)\n", msg.msg_type);
            }
        }
    }

    free(recv_buf);
    return result;
}

/*
 * connect_and_run - one full connection attempt: TCP connect, mTLS
 * handshake, then hand off to the interactive session. Returns the
 * session result on a successful handshake, or SESSION_DISCONNECTED if
 * the connection/handshake itself never got that far (so the caller's
 * retry loop treats "couldn't even connect" the same as "connected then
 * dropped").
 */
/*
 * connected_ok is an out-parameter: set to 1 iff the mTLS handshake
 * actually completed (i.e. we got as far as starting an interactive
 * session), 0 if we never got that far (socket/connect/handshake
 * failure). The caller uses this to decide whether to reset the
 * reconnect backoff delay - a session that connected fine and later
 * dropped means the server/network is reachable, so the next retry
 * should start fast again rather than staying at whatever delay a
 * previous run of *failed* attempts had climbed to.
 */
static session_result connect_and_run(WOLFSSL_CTX *ctx, const char *host,
                                       int port, int *connected_ok)
{
    socket_t sock;
    struct sockaddr_in server_addr;
    WOLFSSL *ssl;
    int rc;
    session_result result;

    *connected_ok = 0;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCKET_INVALID) {
        fprintf(stderr, "socket() failed: %d\n", SOCK_LAST_ERROR());
        return SESSION_DISCONNECTED;
    }

    /* getaddrinfo() rather than inet_pton(): inet_pton() only parses
     * numeric IP address text and does zero name resolution, so it would
     * reject a Tailscale MagicDNS hostname (e.g.
     * "securelink-server.your-tailnet.ts.net") outright with no lookup
     * attempted at all. getaddrinfo() handles both a raw IP (Week 3 Day
     * 3's "hardcoded Tailscale IP" option) and a real hostname (the
     * MagicDNS option) through the same code path, so this doesn't need
     * to be revisited regardless of which addressing approach gets
     * chosen - or if that choice changes later. */
    {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        struct addrinfo *rp;
        char port_str[6];
        int gai_rc;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; /* this project is IPv4-only throughout -
                                     * struct sockaddr_in, not sockaddr_storage */
        hints.ai_socktype = SOCK_STREAM;

        snprintf(port_str, sizeof(port_str), "%d", port);

        gai_rc = getaddrinfo(host, port_str, &hints, &res);
        if (gai_rc != 0) {
            fprintf(stderr, "getaddrinfo failed for host '%s': %s\n",
                    host, gai_strerror(gai_rc));
            CLOSE_SOCKET(sock);
            return SESSION_DISCONNECTED;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        for (rp = res; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) {
                memcpy(&server_addr, rp->ai_addr, sizeof(server_addr));
                break;
            }
        }
        freeaddrinfo(res);

        if (rp == NULL) {
            fprintf(stderr,
                "getaddrinfo: no IPv4 address found for host '%s'\n", host);
            CLOSE_SOCKET(sock);
            return SESSION_DISCONNECTED;
        }
    }

    rc = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc == SOCKET_ERR_RET) {
        fprintf(stderr, "connect() failed: %d\n", SOCK_LAST_ERROR());
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    printf("Connected to server.\n");

    /* See CONN_TIMEOUT_SECONDS above - this is what turns "network died
     * silently mid-session" into an eventual, detectable read failure
     * instead of an indefinite hang. */
    set_socket_timeout(sock);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new failed\n");
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }

    wolfSSL_set_fd(ssl, (int)sock);

    /* wolfSSL frees its handshake arrays once the handshake completes,
     * to save memory - but sl_session_init() (message.c) needs them
     * afterward to derive the per-session HMAC key via
     * wolfSSL_export_keying_material(). Must be called before
     * wolfSSL_connect(), not after - by the time the handshake finishes
     * it's too late to ask wolfSSL to have kept them. */
    wolfSSL_KeepArrays(ssl);

    rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr, "Handshake failed: %s\n",
                wolfSSL_ERR_error_string(err, errbuf));
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    printf("mTLS handshake succeeded.\n");
    *connected_ok = 1;

    result = run_interactive_session(ssl);

    /* Graceful TLS shutdown (sends a close_notify) rather than abruptly
     * freeing the session and closing the socket. Without this, closing
     * a socket that still has unread bytes sitting in its receive buffer
     * (e.g. a post-handshake TLS 1.3 session ticket the client never
     * explicitly read) can make Winsock send a hard RST instead of a
     * graceful FIN - which can abort delivery of whatever we just sent
     * (e.g. a DISCONNECT message) before the peer ever sees it. This
     * call only sends our own close_notify and returns immediately
     * (WOLFSSL_SUCCESS or WOLFSSL_SHUTDOWN_NOT_DONE, not an error) -
     * it deliberately does not block waiting for the peer's close_notify
     * in return, so a peer that's already gone doesn't hang this exit. */
    wolfSSL_shutdown(ssl);

    wolfSSL_free(ssl);
    CLOSE_SOCKET(sock);
    return result;
}

int main(int argc, char *argv[])
{
    WOLFSSL_CTX *ctx = NULL;
    int rc;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    const char *cert_path = NULL;
    const char *key_path = NULL;
    const char *ca_path = NULL;
    int reconnect_delay = RECONNECT_INITIAL_DELAY_SECONDS;

    parse_args(argc, argv, &host, &port, &cert_path, &key_path, &ca_path);

    if (cert_path == NULL || key_path == NULL || ca_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    if (port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port '%d' - must be 1-65535 "
                         "(did -p get a non-numeric value?)\n", port);
        return 1;
    }

#ifdef _WIN32
    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return 1;
    }
#endif

    rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed: %d\n", rc);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
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

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Reconnect loop. ctx (and the certs/keys/CA loaded into it) is
     * reused across attempts - only the TCP socket and WOLFSSL* are
     * per-connection. Every call into connect_and_run() creates a brand
     * new sl_session_state (inside run_interactive_session), which is
     * what makes seq_num correctly start fresh at 0 on every reconnect:
     * the state simply doesn't exist until a new session is established,
     * so there's nothing to reset - it's correct by construction, not by
     * an explicit "reset the counter" step. */
    for (;;) {
        int connected_ok = 0;
        session_result result = connect_and_run(ctx, host, port,
                                                  &connected_ok);

        if (result == SESSION_USER_QUIT) {
            break;
        }

        /* SESSION_DISCONNECTED - either the connection attempt itself
         * failed, or a previously-working session dropped. Either way,
         * back off and retry rather than giving up. If we DID manage to
         * connect this time, the server/network is clearly reachable, so
         * reset the backoff delay back down rather than leaving it at
         * whatever a prior run of failed attempts had climbed to. */
        if (connected_ok) {
            reconnect_delay = RECONNECT_INITIAL_DELAY_SECONDS;
        }

        fprintf(stderr, "Disconnected - retrying in %d second(s)...\n",
                reconnect_delay);
        SLEEP_SECONDS(reconnect_delay);

        reconnect_delay *= 2;
        if (reconnect_delay > RECONNECT_MAX_DELAY_SECONDS) {
            reconnect_delay = RECONNECT_MAX_DELAY_SECONDS;
        }
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
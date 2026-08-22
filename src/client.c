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
#include "hw_expansion.h"
#include "hw_oled.h"
#include "session.h"
#include "ui.h"

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

/* Message framing glue (receive_one_message/send_message) and the
 * interactive session loop that used to live here (single-threaded,
 * client-sends/server-echoes only) have moved to session.h/session.c -
 * see session.h's design comment for why this specific piece became a
 * genuinely shared module instead of staying duplicated between
 * client.c and server.c the way the small portability shim above does. */

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
                                       int port, int *connected_ok, int hw_fd,
                                       int oled_fd)
{
    socket_t sock;
    struct sockaddr_in server_addr;
    WOLFSSL *ssl;
    int rc;
    session_result result;

    *connected_ok = 0;

    /* Case RGB status light (no-op on non-Linux / hardware-absent, see
     * hw_expansion.h) - amber for "attempting", set before the socket
     * even opens so it's lit for the whole connect+handshake attempt,
     * not just the TLS portion of it. */
    hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTING);
    ui_set_status("Connecting...");

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCKET_INVALID) {
        ui_add_historyf(NULL, "socket() failed: %d", SOCK_LAST_ERROR());
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
            ui_add_historyf(NULL, "getaddrinfo failed for host '%s': %s",
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
            ui_add_historyf(NULL,
                "getaddrinfo: no IPv4 address found for host '%s'", host);
            CLOSE_SOCKET(sock);
            return SESSION_DISCONNECTED;
        }
    }

    rc = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc == SOCKET_ERR_RET) {
        ui_add_historyf(NULL, "connect() failed: %d", SOCK_LAST_ERROR());
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    ui_set_status("TCP connected - starting TLS handshake...");

    /* See CONN_TIMEOUT_SECONDS above - this is what turns "network died
     * silently mid-session" into an eventual, detectable read failure
     * instead of an indefinite hang. */
    set_socket_timeout(sock);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        ui_add_history(NULL, "wolfSSL_new failed");
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
        ui_add_historyf(NULL, "Handshake failed: %s",
                         wolfSSL_ERR_error_string(err, errbuf));
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    ui_set_status("mTLS handshake succeeded");
    *connected_ok = 1;
    hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTED);
    hw_oled_draw_text(oled_fd, 0, "SecureLink client");
    hw_oled_draw_text(oled_fd, 1, "Connected");
    hw_oled_display(oled_fd);

    /* Stop the idle-input thread before run_symmetric_session() starts
     * its own reader on the same input_win, and resume it immediately
     * after - see ui.h's "IDLE INPUT" comment. These two calls must
     * bracket every run_symmetric_session() call exactly like this. */
    ui_stop_idle_input();
    result = run_symmetric_session(ssl, sock, hw_fd, oled_fd, "server");
    ui_start_idle_input();

    hw_oled_draw_text(oled_fd, 0, "SecureLink client");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

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
    int hw_fd;
    int oled_fd;

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

    /* SECURITY: nothing printed from here through ui_init() below
     * includes a filesystem path, deliberately - see server.c's
     * matching comment. Confirmed via real physical-console testing
     * that this output is genuinely visible on the touchscreen. */
    rc = wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_certificate_file failed (rc=%d) - check "
            "the -c path was given correctly\n", rc);
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
            "wolfSSL_CTX_use_PrivateKey_file failed (rc=%d) - check "
            "the -k path was given correctly\n", rc);
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
            "wolfSSL_CTX_load_verify_locations failed (rc=%d) - check "
            "the -A path was given correctly\n", rc);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("wolfSSL initialized; certificate, key, and CA loaded.\n");

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Everything from here on runs after the UI takes over the terminal
     * (real ncurses on Linux; unchanged plain console on the dev
     * machine - see ui.h). Every printf/fprintf below this point in
     * main(), connect_and_run(), and session.c has been converted to
     * ui_set_status()/ui_add_history() calls specifically because a
     * stray direct print once ncurses is active would corrupt the
     * screen it manages - see ui.h's top comment. Everything ABOVE this
     * point (argument/cert/CTX setup) deliberately stays plain output,
     * since it can fail before there's any UI to report through. */
    ui_init("server");

    /* Lock-screen interaction (Ctrl+L, PIN entry) needs to work even
     * while disconnected/reconnecting, not just inside an active
     * session - see ui.h's "IDLE INPUT" comment. Started here, once,
     * covering the reconnect loop's idle periods; connect_and_run()
     * brackets each run_symmetric_session() call with the matching
     * stop/start pair. */
    ui_start_idle_input();

    /* Case RGB status light (no-op on non-Linux / hardware-absent - see
     * hw_expansion.h). Opened once here, kept open for the whole
     * reconnect loop below (not re-opened per attempt), since it's a
     * physical device with its own lifecycle independent of any one
     * TCP/TLS session - and closed once at the very end of main().
     * MANUAL_RGB mode must be set before hw_expansion_set_status_color()
     * calls have any visible effect - the board's other modes
     * (rainbow/breathing/etc.) would otherwise override a static color
     * write. */
    hw_fd = hw_expansion_open();
    hw_expansion_set_led_mode(hw_fd, HW_LED_MODE_MANUAL_RGB);
    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);

    /* Case OLED (no-op on non-Linux / hardware-absent - see hw_oled.h),
     * opened once here and kept open for the whole reconnect loop, same
     * "physical device, own lifecycle" reasoning as hw_fd above. Client-
     * side OLED is new as of the two-way redesign - previously only the
     * server had one wired up. */
    oled_fd = hw_oled_open();
    hw_oled_draw_text(oled_fd, 0, "SecureLink client");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

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
                                                  &connected_ok, hw_fd,
                                                  oled_fd);

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

        hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);

        ui_set_statusf("Disconnected - retrying in %d second(s)...",
                       reconnect_delay);
        SLEEP_SECONDS(reconnect_delay);

        reconnect_delay *= 2;
        if (reconnect_delay > RECONNECT_MAX_DELAY_SECONDS) {
            reconnect_delay = RECONNECT_MAX_DELAY_SECONDS;
        }
    }

    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
    hw_expansion_close(hw_fd);
    hw_oled_close(oled_fd);
    ui_stop_idle_input();
    ui_shutdown();

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
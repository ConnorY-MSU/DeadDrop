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
#include "session.h"
#include "ui.h"

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
        ui_add_history(NULL,
            "Verify callback: standard cert-chain verification failed.");
        return 0;
    }

    cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if (cert == NULL) {
        ui_add_history(NULL, "Verify callback: no current cert available.");
        return 0;
    }

    rc = wolfSSL_X509_get_serial_number(cert, serial_bytes, &serial_len);
    if (rc != WOLFSSL_SUCCESS) {
        ui_add_history(NULL,
            "Verify callback: could not read serial number.");
        return 0;
    }

    if (serial_len <= 0 || (size_t)(serial_len * 2) >= sizeof(serial_hex)) {
        ui_add_historyf(NULL,
            "Verify callback: unexpected serial length (%d).", serial_len);
        return 0;
    }

    for (i = 0; i < serial_len; i++) {
        sprintf(&serial_hex[i * 2], "%02X", serial_bytes[i]);
    }
    serial_hex[serial_len * 2] = '\0';

    ui_add_historyf(NULL,
        "Verify callback: checking serial %s against revocation list.",
        serial_hex);

    if (revocation_is_revoked(serial_hex)) {
        ui_add_historyf(NULL,
            "Verify callback: serial %s is REVOKED - rejecting.", serial_hex);
        return 0;
    }

    ui_add_historyf(NULL,
        "Verify callback: serial %s not revoked, proceeding.", serial_hex);
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

/* Message framing glue (receive_one_message/send_message), the
 * msg_type_name() logger helper, and the per-connection message loop
 * that used to live here (handle_connection() - which auto-echoed every
 * TEXT_MESSAGE as "ack: <text>") have moved to session.h/session.c.
 * That auto-ack behavior is gone entirely now, not just relocated: real
 * two-way chat means a human's own typed reply is the acknowledgment,
 * the same way client.c never needed one either. See session.h's design
 * comment for why this piece became a genuinely shared module instead of
 * staying duplicated between client.c and server.c the way the small
 * portability shim above does. */

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

    /* Everything from here on runs after the UI takes over the terminal
     * (real ncurses on Linux; unchanged plain console on the dev
     * machine - see ui.h). Every printf/fprintf below this point in
     * main(), my_verify_callback(), and session.c has been converted to
     * ui_set_status()/ui_add_history() calls specifically because a
     * stray direct print once ncurses is active would corrupt the
     * screen it manages - see ui.h's top comment. Everything ABOVE this
     * point (argument/cert/CTX setup) deliberately stays plain output,
     * since it can fail before there's any UI to report through. */
    ui_init("client");

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == SOCKET_INVALID) {
        ui_add_historyf(NULL, "socket() failed: %d", SOCK_LAST_ERROR());
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
        ui_add_historyf(NULL, "bind() failed: %d", SOCK_LAST_ERROR());
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
        ui_add_historyf(NULL, "listen() failed: %d", SOCK_LAST_ERROR());
        CLOSE_SOCKET(listen_sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    ui_set_statusf("Listening on port %d...", SERVER_PORT);

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
            ui_add_historyf(NULL, "accept() failed: %d", SOCK_LAST_ERROR());
            continue;
        }
        ui_set_status("Client connected - starting TLS handshake...");

        /* See CONN_TIMEOUT_SECONDS above: bounds how long a single stalled
         * or malicious connection can block every other connection,
         * including the legitimate peer's own reconnect attempt. */
        set_socket_timeout(client_sock);

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            ui_add_history(NULL, "wolfSSL_new failed");
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
            ui_add_historyf(NULL, "Handshake failed: %s",
                             wolfSSL_ERR_error_string(err, errbuf));
        } else {
            ui_set_status("mTLS handshake succeeded");
            hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTED);
            hw_oled_draw_text(oled_fd, 0, "SecureLink server");
            hw_oled_draw_text(oled_fd, 1, "Connected");
            hw_oled_display(oled_fd);
            run_symmetric_session(ssl, client_sock, hw_fd, oled_fd, "client");
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
            ui_set_statusf("Listening on port %d...", SERVER_PORT);
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
    ui_shutdown();
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    revocation_free();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
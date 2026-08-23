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
#include "keyshare.h"

#define SERVER_PORT 4433
#define KEYSHARE_PORT 4434 /* mutual key-share protocol - see
                               keyshare.h. Distinct from SERVER_PORT:
                               this is a separate, minimal bootstrap
                               protocol, not part of PROTOCOL.md. */
#define LISTEN_BACKLOG 1

#define SERIAL_BUF_SIZE 32

/* How long a single connection is allowed to sit idle mid-handshake before
 * we give up on it. Without this, a stalled or malicious peer that opens a
 * TCP connection and never completes the handshake blocks this server -
 * which handles exactly one connection at a time - from accepting anyone
 * else, including the legitimate peer's own reconnect attempt. 30s is
 * generous for a real handshake on a slow mobile network, short enough
 * that a stalled connection doesn't lock everyone else out for long.
 *
 * CORRECTION (2026-08-22, found via a live silent-disconnect test - see
 * session.c's SESSION_WATCHDOG_TIMEOUT_SECONDS): this does NOT also catch
 * a peer whose network silently vanished post-handshake, despite an
 * earlier version of this comment claiming it did. session.c's
 * clear_recv_timeout() deliberately resets SO_RCVTIMEO to 0 (block
 * indefinitely) right after the handshake completes, specifically so a
 * normal idle chat session doesn't spuriously disconnect - which means
 * there is no OS-level read timeout left during the actual conversation
 * at all. Confirmed live: with a real silent packet-loss test (iptables
 * DROP, simulating a real power-loss unplug - no FIN/RST ever arrives),
 * the receiver thread's wolfSSL_read() call was confirmed via gdb to
 * still be blocked in the kernel's recv() syscall itself, over 80 seconds
 * later - getsockopt() confirmed SO_RCVTIMEO genuinely was 30s at handshake
 * time, so the value itself was never the problem; it just doesn't apply
 * post-handshake. Detecting THAT failure mode is now session.c's
 * PING-based watchdog's job, not this timeout's. */
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
        ui_add_error(
            "Verify callback: standard cert-chain verification failed.");
        return 0;
    }

    cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if (cert == NULL) {
        ui_add_error("Verify callback: no current cert available.");
        return 0;
    }

    rc = wolfSSL_X509_get_serial_number(cert, serial_bytes, &serial_len);
    if (rc != WOLFSSL_SUCCESS) {
        ui_add_error("Verify callback: could not read serial number.");
        return 0;
    }

    if (serial_len <= 0 || (size_t)(serial_len * 2) >= sizeof(serial_hex)) {
        ui_add_errorf(
            "Verify callback: unexpected serial length (%d).", serial_len);
        return 0;
    }

    for (i = 0; i < serial_len; i++) {
        sprintf(&serial_hex[i * 2], "%02X", serial_bytes[i]);
    }
    serial_hex[serial_len * 2] = '\0';

    /* 2026-08-22: the routine "checking serial.../not revoked, proceeding"
     * notices used to print on EVERY connection - not a security risk in
     * themselves (a certificate serial number is public by design, sent
     * in the clear as part of the cert during any TLS handshake - showing
     * it here doesn't hand an attacker anything they couldn't already
     * read straight off the certificate or a packet capture), but pure
     * noise for an end user: revocation checking still happens on every
     * connection either way, this only ever changed whether the routine
     * "yes, fine" case got printed. Silenced per direct request, alongside
     * the same "stop repeating routine detail on every reconnect" ask
     * applied to session.c's connection-instructions hint. The actual
     * REJECTED-cert case below stays visible - that's a real security
     * event a user should see, not routine confirmation noise. */
    if (revocation_is_revoked(serial_hex)) {
        ui_add_errorf(
            "Verify callback: serial %s is REVOKED - rejecting.", serial_hex);
        return 0;
    }

    return 1;
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <server_cert.pem> -A <ca_cert.pem> "
        "-r <revoked_serials.txt>\n"
        "         (-k <server_key.pem> | -K <keyshare_dir> -P <peer_ip> "
        "-N <peer_hostname>)\n"
        "-c/-A/-r are always required. For the private key, use EITHER:\n"
        "  -k <path>   a plain PEM key file (dev-machine testing, or a\n"
        "              device without mutual key-share protection set up)\n"
        "or:\n"
        "  -K <dir> -P <peer_ip> -N <peer_hostname>\n"
        "              the mutual key-share flow (see keyshare.h) - <dir>\n"
        "              must contain key.enc, share_local.bin, and\n"
        "              peer_custody_share.bin; <peer_ip>/<peer_hostname>\n"
        "              identify the paired device to fetch the share from.\n"
        "There are no default paths, since a hardcoded path baked into the\n"
        "binary would tie it to one machine and break the moment this runs\n"
        "on a different device.\n",
        prog_name);
}

static void parse_args(int argc, char *argv[],
                        const char **cert_path, const char **key_path,
                        const char **ca_path, const char **revoked_path,
                        const char **keyshare_dir, const char **peer_ip,
                        const char **peer_hostname)
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
        } else if (strcmp(argv[i], "-K") == 0) {
            *keyshare_dir = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0) {
            *peer_ip = argv[++i];
        } else if (strcmp(argv[i], "-N") == 0) {
            *peer_hostname = argv[++i];
        }
    }
}

/* load_private_key - either a plain PEM file (-k, dev-machine testing
 * or a device without mutual key-share protection set up) or the
 * mutual key-share flow (-K/-P/-N, see keyshare.h) - decrypted into a
 * stack buffer, loaded via wolfSSL_CTX_use_PrivateKey_buffer(), and
 * zeroed immediately after, rather than ever touching disk in
 * plaintext. Returns 0 on success. */
static int load_private_key(WOLFSSL_CTX *ctx, const char *key_path,
                             const char *keyshare_dir, const char *peer_ip,
                             const char *peer_hostname)
{
    int rc;

    if (keyshare_dir != NULL) {
        char path_buf[600];
        uint8_t K[KEYSHARE_LEN];
        uint8_t pem_buf[8192];
        long pem_len;

        snprintf(path_buf, sizeof(path_buf), "%s/share_local.bin", keyshare_dir);
        {
            char custody_path[600];
            char key_enc_path[600];
            snprintf(custody_path, sizeof(custody_path),
                      "%s/peer_custody_share.bin", keyshare_dir);
            snprintf(key_enc_path, sizeof(key_enc_path), "%s/key.enc",
                      keyshare_dir);

            printf("Fetching this device's key-share from its paired "
                    "device over Tailscale (retrying until it's "
                    "reachable)...\n");
            fflush(stdout);
            rc = keyshare_reconstruct(path_buf, peer_ip, peer_hostname,
                                        custody_path, KEYSHARE_PORT, K);
            if (rc != 0) {
                fprintf(stderr, "keyshare_reconstruct failed - check "
                        "the -K directory's files exist and are "
                        "readable\n");
                return -1;
            }
            printf("Key-share reconstructed.\n");
            fflush(stdout);

            pem_len = keyshare_decrypt_private_key(key_enc_path, K, pem_buf,
                                                     sizeof(pem_buf));
            memset(K, 0, sizeof(K));
            if (pem_len < 0) {
                fprintf(stderr, "keyshare_decrypt_private_key failed - "
                        "check the -K directory's key.enc file\n");
                return -1;
            }
        }

        rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, pem_buf, pem_len,
                                                 WOLFSSL_FILETYPE_PEM);
        memset(pem_buf, 0, sizeof(pem_buf));
        if (rc != WOLFSSL_SUCCESS) {
            fprintf(stderr,
                "wolfSSL_CTX_use_PrivateKey_buffer failed (rc=%d)\n", rc);
            return -1;
        }
        return 0;
    }

    rc = wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_PrivateKey_file failed (rc=%d) - check "
            "the -k path was given correctly\n", rc);
        return -1;
    }
    return 0;
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
    const char *keyshare_dir = NULL;
    const char *peer_ip = NULL;
    const char *peer_hostname = NULL;
    int hw_fd;
    int oled_fd;

    parse_args(argc, argv, &cert_path, &key_path, &ca_path, &revoked_path,
               &keyshare_dir, &peer_ip, &peer_hostname);

    if (cert_path == NULL || ca_path == NULL || revoked_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }
    if (keyshare_dir != NULL) {
        if (peer_ip == NULL || peer_hostname == NULL) {
            fprintf(stderr, "-K requires -P and -N too\n");
            print_usage(argv[0]);
            return 1;
        }
    } else if (key_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    /* SECURITY: nothing printed from here through ui_init() below
     * includes a filesystem path, deliberately - confirmed via real
     * physical-console testing that this output is genuinely visible
     * on the touchscreen (this project's whole point), not just a
     * development-time convenience. A device meant to sit somewhere
     * semi-public shouldn't hand a casual observer the exact on-disk
     * layout of its own private key material - real info found and
     * fixed the same day it was noticed, not a hypothetical concern. */
    rc = revocation_load(revoked_path);
    if (rc != 0) {
        fprintf(stderr,
            "Warning: loading the revoked-serials list failed - all "
            "certs will be treated as revoked until this is fixed.\n");
    } else {
        printf("Loaded revoked-serials list.\n");
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
            "wolfSSL_CTX_use_certificate_file failed (rc=%d) - check "
            "the -c path was given correctly\n", rc);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (load_private_key(ctx, key_path, keyshare_dir, peer_ip,
                          peer_hostname) != 0) {
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    /* Deliberately NOT calling keyshare_stop_listener() here - see its
     * doc comment in keyshare.h for the real deadlock this caused the
     * first time around. The listener stays up for this process's
     * whole lifetime, so the peer can fetch its own share from THIS
     * device at any later point too, including after its own
     * independent reboot. */

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
    ui_init("bravo");

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == SOCKET_INVALID) {
        ui_add_errorf("socket() failed: %d", SOCK_LAST_ERROR());
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
        ui_add_errorf("bind() failed: %d", SOCK_LAST_ERROR());
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
        ui_add_errorf("listen() failed: %d", SOCK_LAST_ERROR());
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
    ui_set_link_state(0);

    /* Case OLED (no-op on non-Linux / hardware-absent - see hw_oled.h),
     * same "opened once, lives for the whole process" reasoning as the
     * RGB light above. Shows a simple idle message rather than a blank
     * screen, so it's obvious at a glance the service is actually
     * running, not just that the screen happens to be off. */
    oled_fd = hw_oled_open();
    ui_set_oled_fd(oled_fd); /* one-time wiring so ui.c's touch thread
        can periodically refresh background network metrics below
        this file's own role/status lines - see ui.h. */
    hw_oled_draw_text(oled_fd, 0, "SecureLink alpha");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

    /* Lock-screen interaction (Ctrl+L, PIN entry) needs to work even
     * while no client has connected yet - accept() below blocks
     * indefinitely with no input polling of its own - see ui.h's
     * "IDLE INPUT" comment. Started here, once, covering every gap
     * between connections; each run_symmetric_session() call below is
     * bracketed with the matching stop/start pair. */
    ui_start_idle_input();

    for (;;) {
        socket_t client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == SOCKET_INVALID) {
            ui_add_errorf("accept() failed: %d", SOCK_LAST_ERROR());
            continue;
        }
        ui_set_status("bravo connected - starting TLS handshake...");

        /* See CONN_TIMEOUT_SECONDS above: bounds how long a single stalled
         * or malicious connection can block every other connection,
         * including the legitimate peer's own reconnect attempt. */
        set_socket_timeout(client_sock);

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            ui_add_error("wolfSSL_new failed");
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
            ui_add_errorf("Handshake failed: %s",
                           wolfSSL_ERR_error_string(err, errbuf));
        } else {
            ui_set_status("mTLS handshake succeeded");
            hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTED);
            ui_set_link_state(1);
            hw_oled_draw_text(oled_fd, 0, "SecureLink alpha");
            hw_oled_draw_text(oled_fd, 1, "Connected");
            hw_oled_display(oled_fd);
            /* Stop the idle-input thread before run_symmetric_session()
             * starts its own reader on the same input_win, and resume
             * it immediately after - see ui.h's "IDLE INPUT" comment.
             * These two calls must bracket every run_symmetric_session()
             * call exactly like this. */
            ui_stop_idle_input();
            run_symmetric_session(ssl, client_sock, hw_fd, oled_fd, "bravo");
            ui_start_idle_input();
            hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
            ui_set_link_state(0);
            hw_oled_draw_text(oled_fd, 0, "SecureLink alpha");
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
    ui_stop_idle_input();
    ui_shutdown();
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    revocation_free();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
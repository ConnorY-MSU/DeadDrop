#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Portability shim: Winsock vs POSIX socket differences live only here; rest of the file uses the portable names on the right. */
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
#include "wardrive.h"
#include "session.h"
#include "ui.h"
#include "keyshare.h"

#define SERVER_PORT 4433
#define KEYSHARE_PORT 4434 /* mutual key-share protocol (see keyshare.h); separate minimal bootstrap protocol, not part of PROTOCOL.md */
/* OS accept-queue backlog. Raised from 1 after real bug (silent drop under concurrent connects). See COMMENT_ARCHIVE.md. */
#define LISTEN_BACKLOG 8

#define SERIAL_BUF_SIZE 32

/* Idle mid-handshake timeout; does NOT cover post-handshake silence (see session.c's PING watchdog). See COMMENT_ARCHIVE.md. */
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

/* ASSUMPTION: single-level PKI, no intermediate CAs (see docs/PKI_SETUP.md) - revisit if one is ever added. */
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

    /* Routine "not revoked" notices silenced (pure noise); the REJECTED case below stays visible as a real security event. */
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

/* load_private_key - loads via -k (plain PEM) or -K/-P/-N (mutual key-share flow, see keyshare.h); decrypts into a stack buffer zeroed right after use. Returns 0 on success. */
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

            /* Runs after ui_init()/ui_start_idle_input() so this unbounded wait doesn't corrupt ncurses and Ctrl+W WiFi setup stays available. */
            ui_add_history(NULL,
                "Fetching this device's key-share from its paired "
                "device over Tailscale (retrying until it's "
                "reachable)...");
            rc = keyshare_reconstruct(path_buf, peer_ip, peer_hostname,
                                        custody_path, KEYSHARE_PORT, K);
            if (rc != 0) {
                ui_add_error("keyshare_reconstruct failed - check "
                              "the -K directory's files exist and are "
                              "readable");
                return -1;
            }
            ui_add_history(NULL, "Key-share reconstructed.");

            pem_len = keyshare_decrypt_private_key(key_enc_path, K, pem_buf,
                                                     sizeof(pem_buf));
            memset(K, 0, sizeof(K));
            if (pem_len < 0) {
                ui_add_error("keyshare_decrypt_private_key failed - "
                              "check the -K directory's key.enc file");
                return -1;
            }
        }

        rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx, pem_buf, pem_len,
                                                 WOLFSSL_FILETYPE_PEM);
        memset(pem_buf, 0, sizeof(pem_buf));
        if (rc != WOLFSSL_SUCCESS) {
            ui_add_errorf(
                "wolfSSL_CTX_use_PrivateKey_buffer failed (rc=%d)", rc);
            return -1;
        }
        return 0;
    }

    rc = wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        ui_add_errorf(
            "wolfSSL_CTX_use_PrivateKey_file failed (rc=%d) - check "
            "the -k path was given correctly", rc);
        return -1;
    }
    return 0;
}

/* Message framing, msg_type_name(), and the per-connection message loop moved to session.h/session.c (shared with client.c); old auto-ack behavior is gone, not just relocated. */

#ifndef _WIN32
/* Identical to client.c's copy of this helper (duplicated per this file's small-helper convention) - see there for the timing/bound reasoning. */
#define CLOUD_INIT_WAIT_MAX_MS 15000
#define CLOUD_INIT_WAIT_POLL_MS 250

static void wait_for_cloud_init_boot_finished(void)
{
    int waited_ms = 0;
    while (access("/var/lib/cloud/instance/boot-finished", F_OK) != 0 &&
           waited_ms < CLOUD_INIT_WAIT_MAX_MS) {
        usleep(CLOUD_INIT_WAIT_POLL_MS * 1000);
        waited_ms += CLOUD_INIT_WAIT_POLL_MS;
    }
}
#endif

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

    /* SECURITY: nothing printed here through ui_init() includes a filesystem path, so a semi-public device doesn't leak its key layout. */
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

    /* ui_init()/ui_start_idle_input() moved up here (before cert/key/CA loading) so Ctrl+W WiFi setup works even if load_private_key() blocks. See client.c's matching comment; see COMMENT_ARCHIVE.md. */
#ifndef _WIN32
    wait_for_cloud_init_boot_finished();
#endif
    /* This literal is the single source of truth for every "Alpha"/"Bravo" display site; ui_init() infers this device's identity from it too. */
    ui_init("Bravo");
    ui_start_idle_input();
    ui_set_status("Loading credentials...");

    rc = wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        ui_add_errorf(
            "wolfSSL_CTX_use_certificate_file failed (rc=%d) - check "
            "the -c path was given correctly", rc);
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
    /* Deliberately NOT calling keyshare_stop_listener() here (caused a deadlock before, see keyshare.h) - listener stays up for the process's lifetime. */

    rc = wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (rc != WOLFSSL_SUCCESS) {
        ui_add_errorf(
            "wolfSSL_CTX_load_verify_locations failed (rc=%d) - check "
            "the -A path was given correctly", rc);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    ui_add_history(NULL,
        "wolfSSL initialized; certificate, key, and CA loaded.");
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        my_verify_callback);

    /* ui_init() already ran - from here on use ui_set_status()/ui_add_history(), not fprintf/printf, to avoid corrupting the ncurses screen. */
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
    server_addr.sin_port = htons(SERVER_PORT);

    /* Bind to the Tailscale IP, not INADDR_ANY, so the tailnet ACL actually scopes who can attempt a handshake; fail-closed if it can't be determined. Windows dev builds keep INADDR_ANY. See COMMENT_ARCHIVE.md. */
#ifdef __linux__
    {
        char ts_ip[64];
        if (keyshare_get_own_tailscale_ip(ts_ip, sizeof(ts_ip)) != 0) {
            ui_add_error("Could not determine this device's Tailscale IP - "
                "refusing to start rather than bind an unscoped listener "
                "(see server.c's bind() comment).");
            CLOSE_SOCKET(listen_sock);
            wolfSSL_CTX_free(ctx);
            wolfSSL_Cleanup();
            return 1;
        }
        if (inet_pton(AF_INET, ts_ip, &server_addr.sin_addr) != 1) {
            ui_add_errorf("Tailscale IP '%s' failed to parse - refusing to "
                "start.", ts_ip);
            CLOSE_SOCKET(listen_sock);
            wolfSSL_CTX_free(ctx);
            wolfSSL_Cleanup();
            return 1;
        }
    }
#else
    server_addr.sin_addr.s_addr = INADDR_ANY;
#endif

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

    /* Case RGB status light (no-op without hardware, see hw_expansion.h); opened once here, not per-connection - see client.c's matching comment. */
    hw_fd = hw_expansion_open();
    hw_expansion_set_led_mode(hw_fd, HW_LED_MODE_MANUAL_RGB);
    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
    ui_set_link_state(0);

    /* Case OLED (no-op without hardware - see hw_oled.h), opened once like the RGB light above; shows an idle message while waiting. */
    oled_fd = hw_oled_open();
    ui_set_oled_fd(oled_fd); /* one-time wiring so ui.c can refresh background network metrics below this file's own role/status lines - see ui.h */
    hw_oled_draw_text(oled_fd, 0, "DeadDrop Alpha");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

    /* Resident Piper TTS pipeline + speaker thread, started once for the process's life; failure here is silently non-fatal (hw_tts_speak() becomes a no-op). */
    hw_tts_init();

    /* Background wardrive thread - starts either way, but stays idle (OFF) unless a prior "/wardrive on" persisted it enabled. See wardrive.h. */
    wardrive_init();

    /* ui_start_idle_input() is already running (started earlier); covers accept()'s block below. Each run_symmetric_session() call still brackets its own stop/start. */

    for (;;) {
        socket_t client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == SOCKET_INVALID) {
            ui_add_errorf("accept() failed: %d", SOCK_LAST_ERROR());
            continue;
        }

        /* BUGFIX (2026-09-23): idle-input MUST stop before the first UI
         * call touches input_win, not just before run_symmetric_session().
         * The idle thread re-locks ui_mutex every ~20ms in a tight loop
         * (see UI_POLL_SLICE_MS) with no fairness guarantee, so leaving
         * it running through the whole accept()+handshake window let it
         * starve this thread's ui_set_status() below indefinitely - a
         * real, reproduced hang, not a theoretical race. Restarted once
         * at the end of this iteration, on every exit path. See
         * COMMENT_ARCHIVE.md. */
        ui_stop_idle_input();
        ui_set_status("bravo connected - starting TLS handshake...");

        /* See CONN_TIMEOUT_SECONDS above: bounds how long one stalled/malicious connection can block every other connection. */
        set_socket_timeout(client_sock);

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            ui_add_error("wolfSSL_new failed");
            CLOSE_SOCKET(client_sock);
            ui_start_idle_input();
            continue;
        }

        wolfSSL_set_fd(ssl, (int)client_sock);

        /* See client.c's matching comment: session.c needs wolfSSL's handshake arrays afterward for the per-session HMAC key; must be called before wolfSSL_accept(). */
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
            hw_oled_draw_text(oled_fd, 0, "DeadDrop Alpha");
            hw_oled_draw_text(oled_fd, 1, "Connected");
            hw_oled_display(oled_fd);
            run_symmetric_session(ssl, client_sock, hw_fd, oled_fd, "Bravo");
            hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
            ui_set_link_state(0);
            hw_oled_draw_text(oled_fd, 0, "DeadDrop Alpha");
            hw_oled_draw_text(oled_fd, 1, "Waiting...");
            hw_oled_display(oled_fd);

            /* See client.c's matching comment: graceful close_notify avoids a hard RST that could abort delivery of unread buffered data; best-effort, non-blocking. */
            wolfSSL_shutdown(ssl);
            ui_set_statusf("Listening on port %d...", SERVER_PORT);
        }

        ui_start_idle_input();
        wolfSSL_free(ssl);
        CLOSE_SOCKET(client_sock);
    }

    /* KNOWN GAP: the loop above never breaks, so this cleanup is unreachable today (no signal handler; abrupt kill). Revisit in Week 4. See COMMENT_ARCHIVE.md. */
    CLOSE_SOCKET(listen_sock);
    hw_expansion_close(hw_fd);
    hw_oled_close(oled_fd);
    hw_tts_shutdown();
    wardrive_shutdown();
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
#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Portability shim - matches server.c; runs here (Windows) and unchanged on the Pi (Linux). */
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
    #include <fcntl.h>
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
#include "hw_tts.h"
#include "session.h"
#include "ui.h"
#include "keyshare.h"

#define KEYSHARE_PORT 4434 /* must match server.c's - see keyshare.h */

/* Host/port default to loopback; cert/key/CA paths have no default (hardcoded path only works on one machine, same as server.c). */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433

/* Bounds a stalled pre-handshake attempt only - reset to 0 once a session is live; the PING watchdog handles a silently dropped peer instead. Same value as server.c. */
#define CONN_TIMEOUT_SECONDS 30

/* Reconnect backoff: start at 1s, double each failure, cap at 30s. */
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

/* A blocking connect() to a dead peer can hang for a minute+; connect_with_timeout() below bounds it via non-blocking connect + select(). See COMMENT_ARCHIVE.md. */
#define CONNECT_TIMEOUT_SECONDS 8

static int set_nonblocking(socket_t s, int enable)
{
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (enable) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(s, F_SETFL, flags) == 0 ? 0 : -1;
#endif
}

/* Returns 0 on success, -1 on failure (timeout or a real connect error); SOCK_LAST_ERROR() reflects the actual reason either way. */
static int connect_with_timeout(socket_t s, const struct sockaddr *addr,
                                  size_t addr_len)
{
    int rc;

    if (set_nonblocking(s, 1) != 0) {
        return -1; /* couldn't switch to non-blocking - treated as a hard error */
    }

    rc = connect(s, addr, (socklen_t)addr_len);
    if (rc == 0) {
        set_nonblocking(s, 0); /* connected immediately (e.g. localhost) - still restore blocking mode */
        return 0;
    }

#ifdef _WIN32
    if (SOCK_LAST_ERROR() != WSAEWOULDBLOCK) {
        return -1;
    }
#else
    if (SOCK_LAST_ERROR() != EINPROGRESS) {
        return -1;
    }
#endif

    {
        fd_set wfds;
        struct timeval tv;
        int sel_rc;

        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        tv.tv_sec = CONNECT_TIMEOUT_SECONDS;
        tv.tv_usec = 0;

        sel_rc = select((int)(s + 1), NULL, &wfds, NULL, &tv);
        if (sel_rc <= 0) {
            /* 0 = our own timeout elapsed; <0 = a real select() error - either way, didn't complete in time. */
            set_nonblocking(s, 0);
            return -1;
        }
    }

    {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != 0 ||
                err != 0) {
            set_nonblocking(s, 0);
            return -1;
        }
    }

    set_nonblocking(s, 0);
    return 0;
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <client_cert.pem> -A <ca_cert.pem> "
        "[-h <host>] [-p <port>]\n"
        "         (-k <client_key.pem> | -K <keyshare_dir> -P <peer_ip> "
        "-N <peer_hostname>)\n"
        "-c/-A are always required. For the private key, use EITHER:\n"
        "  -k <path>   a plain PEM key file (dev-machine testing, or a\n"
        "              device without mutual key-share protection set up)\n"
        "or:\n"
        "  -K <dir> -P <peer_ip> -N <peer_hostname>\n"
        "              the mutual key-share flow (see keyshare.h) - <dir>\n"
        "              must contain key.enc, share_local.bin, and\n"
        "              peer_custody_share.bin; <peer_ip>/<peer_hostname>\n"
        "              identify the paired device to fetch the share from.\n"
        "-h/-p default to %s:%d if omitted.\n",
        prog_name, DEFAULT_HOST, DEFAULT_PORT);
}

static void parse_args(int argc, char *argv[],
                        const char **host, int *port,
                        const char **cert_path, const char **key_path,
                        const char **ca_path, const char **keyshare_dir,
                        const char **peer_ip, const char **peer_hostname)
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
        } else if (strcmp(argv[i], "-K") == 0) {
            *keyshare_dir = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0) {
            *peer_ip = argv[++i];
        } else if (strcmp(argv[i], "-N") == 0) {
            *peer_hostname = argv[++i];
        }
    }
}

/* Message framing and the interactive session loop moved to session.h/session.c as a shared module. */

/* load_private_key - loads via plain PEM (-k) or the mutual key-share flow (-K/-P/-N, see keyshare.h). Duplicated from server.c. Returns 0 on success. */
static int load_private_key(WOLFSSL_CTX *ctx, const char *key_path,
                             const char *keyshare_dir, const char *peer_ip,
                             const char *peer_hostname)
{
    int rc;

    if (keyshare_dir != NULL) {
        char local_share_path[600];
        char custody_path[600];
        char key_enc_path[600];
        uint8_t K[KEYSHARE_LEN];
        uint8_t pem_buf[8192];
        long pem_len;

        snprintf(local_share_path, sizeof(local_share_path),
                  "%s/share_local.bin", keyshare_dir);
        snprintf(custody_path, sizeof(custody_path),
                  "%s/peer_custody_share.bin", keyshare_dir);
        snprintf(key_enc_path, sizeof(key_enc_path), "%s/key.enc",
                  keyshare_dir);

        /* ui_add_history()/ui_add_error(), not printf, so this potentially-blocking wait doesn't corrupt the ncurses screen. */
        ui_add_history(NULL,
            "Fetching this device's key-share from its paired device "
            "over Tailscale (retrying until it's reachable)...");
        rc = keyshare_reconstruct(local_share_path, peer_ip, peer_hostname,
                                    custody_path, KEYSHARE_PORT, K);
        if (rc != 0) {
            ui_add_error("keyshare_reconstruct failed - check the "
                          "-K directory's files exist and are readable");
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

/* connect_and_run - one full connection attempt (TCP connect, mTLS handshake, interactive session). Returns SESSION_DISCONNECTED if it never reached a handshake; connected_ok (out) is set to 1 iff the handshake completed. */
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

    /* Case RGB status light (no-op if absent, see hw_expansion.h) - amber for "attempting". */
    hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTING);
    ui_set_status("Connecting...");

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCKET_INVALID) {
        ui_add_errorf("socket() failed: %d", SOCK_LAST_ERROR());
        return SESSION_DISCONNECTED;
    }

    /* getaddrinfo() not inet_pton(), which would reject a Tailscale MagicDNS hostname - handles both a raw IP and a hostname. */
    {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        struct addrinfo *rp;
        char port_str[6];
        int gai_rc;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; /* this project is IPv4-only throughout */
        hints.ai_socktype = SOCK_STREAM;

        snprintf(port_str, sizeof(port_str), "%d", port);

        gai_rc = getaddrinfo(host, port_str, &hints, &res);
        if (gai_rc != 0) {
            ui_add_errorf("getaddrinfo failed for host '%s': %s",
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
            ui_add_errorf(
                "getaddrinfo: no IPv4 address found for host '%s'", host);
            CLOSE_SOCKET(sock);
            return SESSION_DISCONNECTED;
        }
    }

    rc = connect_with_timeout(sock, (struct sockaddr *)&server_addr,
                                sizeof(server_addr));
    if (rc != 0) {
        ui_add_errorf("connect() failed or timed out after %ds: %d",
                       CONNECT_TIMEOUT_SECONDS, SOCK_LAST_ERROR());
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    ui_set_status("TCP connected - starting TLS handshake...");

    /* See CONN_TIMEOUT_SECONDS above - turns a silent network death into a detectable read failure instead of an indefinite hang. */
    set_socket_timeout(sock);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        ui_add_error("wolfSSL_new failed");
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }

    wolfSSL_set_fd(ssl, (int)sock);

    /* wolfSSL frees its handshake arrays after completion, but dd_session_init() needs them - must be called before wolfSSL_connect(). */
    wolfSSL_KeepArrays(ssl);

    rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        ui_add_errorf("Handshake failed: %s",
                       wolfSSL_ERR_error_string(err, errbuf));
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return SESSION_DISCONNECTED;
    }
    ui_set_status("mTLS handshake succeeded");
    *connected_ok = 1;
    hw_expansion_set_status_color(hw_fd, HW_STATUS_CONNECTED);
    ui_set_link_state(1);
    hw_oled_draw_text(oled_fd, 0, "DeadDrop Bravo");
    hw_oled_draw_text(oled_fd, 1, "Connected");
    hw_oled_display(oled_fd);

    /* Stop the idle-input thread before run_symmetric_session() reads input_win; resume right after (see ui.h "IDLE INPUT"). */
    ui_stop_idle_input();
    result = run_symmetric_session(ssl, sock, hw_fd, oled_fd, "Alpha");
    ui_start_idle_input();

    hw_oled_draw_text(oled_fd, 0, "DeadDrop Bravo");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

    /* Graceful TLS shutdown (close_notify), not an abrupt close - unread socket bytes can make Winsock send a hard RST instead. Doesn't wait for the peer's close_notify. */
    wolfSSL_shutdown(ssl);

    wolfSSL_free(ssl);
    CLOSE_SOCKET(sock);
    return result;
}

#ifndef _WIN32
/* How long to wait for cloud-init's "boot-finished" marker before giving up and drawing the splash anyway. Usually returns almost immediately. */
#define CLOUD_INIT_WAIT_MAX_MS 15000
#define CLOUD_INIT_WAIT_POLL_MS 250

/* Cloud-init's final stage can write status text to this console after ui_init() takes over, corrupting the splash; wait for cloud-init's "done" sentinel first. See COMMENT_ARCHIVE.md. */
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
    const char *keyshare_dir = NULL;
    const char *peer_ip = NULL;
    const char *peer_hostname = NULL;
    int reconnect_delay = RECONNECT_INITIAL_DELAY_SECONDS;
    int hw_fd;
    int oled_fd;

    parse_args(argc, argv, &host, &port, &cert_path, &key_path, &ca_path,
               &keyshare_dir, &peer_ip, &peer_hostname);

    if (cert_path == NULL || ca_path == NULL) {
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

    /* ui_init()/ui_start_idle_input() run here, before credential loading, so Ctrl+W WiFi setup is available if load_private_key() blocks a long time. See COMMENT_ARCHIVE.md. */
#ifndef _WIN32
    wait_for_cloud_init_boot_finished();
#endif
    /* "Alpha"/"Bravo" capitalized consistently everywhere either name is displayed (see ui_init()'s comment on inferring identity). */
    ui_init("Alpha");
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
    /* Deliberately NOT calling keyshare_stop_listener() - see keyshare.h for the deadlock this caused. Listener stays up for the process's lifetime. */

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

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Restores the "about to connect" status now that credential loading has finished, overwriting "Loading credentials..." above. */
    ui_set_status("Connecting to alpha...");

    /* Case RGB status light (no-op if absent, see hw_expansion.h) - opened once, kept open for the reconnect loop, closed at end of main(). */
    hw_fd = hw_expansion_open();
    hw_expansion_set_led_mode(hw_fd, HW_LED_MODE_MANUAL_RGB);
    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
    ui_set_link_state(0);

    /* Case OLED (no-op if absent, see hw_oled.h) - opened once, kept open for the reconnect loop, same reasoning as hw_fd above. */
    oled_fd = hw_oled_open();
    ui_set_oled_fd(oled_fd); /* one-time wiring so ui.c's touch thread can refresh OLED metrics - see ui.h. */
    hw_oled_draw_text(oled_fd, 0, "DeadDrop Bravo");
    hw_oled_draw_text(oled_fd, 1, "Waiting...");
    hw_oled_display(oled_fd);

    /* Resident Piper TTS pipeline + speaker thread; failure here (piper/aplay missing) is silently non-fatal - hw_tts_speak() becomes a no-op. */
    hw_tts_init();

    /* Reconnect loop. ctx is reused across attempts; only the socket and WOLFSSL* are per-connection. */
    for (;;) {
        int connected_ok = 0;
        session_result result = connect_and_run(ctx, host, port,
                                                  &connected_ok, hw_fd,
                                                  oled_fd);

        if (result == SESSION_USER_QUIT) {
            break;
        }

        /* Either the connect failed or a working session dropped - back off and retry; reset the delay if we did connect this time. */
        if (connected_ok) {
            reconnect_delay = RECONNECT_INITIAL_DELAY_SECONDS;
        }

        hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
        ui_set_link_state(0);

        ui_set_statusf("Disconnected - retrying in %d second(s)...",
                       reconnect_delay);
        SLEEP_SECONDS(reconnect_delay);

        reconnect_delay *= 2;
        if (reconnect_delay > RECONNECT_MAX_DELAY_SECONDS) {
            reconnect_delay = RECONNECT_MAX_DELAY_SECONDS;
        }
    }

    hw_expansion_set_status_color(hw_fd, HW_STATUS_DISCONNECTED);
    ui_set_link_state(0);
    hw_expansion_close(hw_fd);
    hw_oled_close(oled_fd);
    hw_tts_shutdown();
    ui_stop_idle_input();
    ui_shutdown();

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
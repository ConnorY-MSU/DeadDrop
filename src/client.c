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
#include "session.h"
#include "ui.h"
#include "keyshare.h"

#define KEYSHARE_PORT 4434 /* must match server.c's - see keyshare.h */

/* Host/port are generic, sensible defaults (loopback, this project's
 * standard port) - not tied to any one machine, so they're fine to keep
 * as defaults. Cert/key/CA paths are NOT: a hardcoded absolute path
 * only ever works on the machine it was typed on, so those are required
 * arguments with no default, same reasoning as server.c. */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433

/* Same value server.c applies to its side of each connection - bounds a
 * stalled pre-handshake connect/handshake attempt only. See server.c's
 * matching #define comment (2026-08-22 correction) for why this does NOT
 * also catch a post-handshake silent network loss - session.c's
 * clear_recv_timeout() deliberately resets this to 0 (block indefinitely)
 * once a session is live, and session.c's PING-based watchdog is what
 * actually catches a peer whose network vanished silently mid-chat. */
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

/* REAL BUG FOUND AND FIXED (2026-08-22, live physical-unplug test series):
 * a plain blocking connect() to a genuinely powered-off peer doesn't fail
 * quickly - there's no host to send a TCP RST, so the OS just keeps
 * retransmitting the initial SYN with its own exponential backoff
 * (confirmed live via `ss -ti`: SYN-SENT, backoff climbing, rto growing
 * toward 60+ seconds) until its own internal retry budget (platform-
 * dependent, commonly a minute or more) is exhausted. Since this call
 * was never given its own timeout (SO_RCVTIMEO/SO_SNDTIMEO are only set
 * AFTER a successful connect(), by set_socket_timeout() above), a fresh
 * reconnect attempt against a still-dead peer could block for a long
 * time in "Connecting..." (amber) - not wrong, exactly, but far less
 * responsive than RECONNECT_INITIAL_DELAY_SECONDS' fast-retry design
 * intends, and the outer reconnect backoff barely gets to run since this
 * inner call eats most of the time.
 *
 * Fixed with the standard portable technique: switch to non-blocking
 * right before connect(), let it return immediately (EINPROGRESS/
 * EWOULDBLOCK is the expected, non-error result), use select() to wait
 * up to CONNECT_TIMEOUT_SECONDS for the socket to become writable (the
 * signal a non-blocking connect() has resolved, one way or the other),
 * then check SO_ERROR to find out whether it actually succeeded. Restores
 * blocking mode afterward - everything past this point (the handshake,
 * the session) still assumes a blocking socket, unchanged. */
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

/* Returns 0 on success, -1 on failure (timeout or a real connect error) -
 * SOCK_LAST_ERROR() reflects the actual reason either way (ETIMEDOUT-ish
 * for our own timeout path, or whatever SO_ERROR reported). */
static int connect_with_timeout(socket_t s, const struct sockaddr *addr,
                                  size_t addr_len)
{
    int rc;

    if (set_nonblocking(s, 1) != 0) {
        return -1; /* couldn't even switch modes - fall through to a
            regular blocking connect() at the call site would be nicer,
            but this is not expected to fail on any real platform this
            project targets, so treating it as a hard error is simpler
            and honest about an unexpected condition. */
    }

    rc = connect(s, addr, (socklen_t)addr_len);
    if (rc == 0) {
        set_nonblocking(s, 0); /* connected immediately (e.g. localhost) -
            still restore blocking mode for everything after this */
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
            /* 0 = our own timeout elapsed; <0 = a real select() error -
             * either way, this attempt didn't complete in time. */
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

/* Message framing glue (receive_one_message/send_message) and the
 * interactive session loop that used to live here (single-threaded,
 * client-sends/server-echoes only) have moved to session.h/session.c -
 * see session.h's design comment for why this specific piece became a
 * genuinely shared module instead of staying duplicated between
 * client.c and server.c the way the small portability shim above does. */

/* load_private_key - either a plain PEM file (-k) or the mutual
 * key-share flow (-K/-P/-N, see keyshare.h) - decrypted into a stack
 * buffer, loaded via wolfSSL_CTX_use_PrivateKey_buffer(), and zeroed
 * immediately after, rather than ever touching disk in plaintext.
 * Identical to server.c's own copy of this helper - small enough that
 * duplicating it matches this project's established convention for
 * per-file helpers (parse_args, print_usage) rather than adding a
 * third shared module just for this. Returns 0 on success. */
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

        /* Runs after ui_init()/ui_start_idle_input() now (see main()'s
         * own comment on why that moved earlier) - ui_add_history()/
         * ui_add_error(), not printf/fprintf, so a real, possibly very
         * long wait here (keyshare_reconstruct()'s retry loop has no
         * timeout) doesn't corrupt the ncurses screen, and the idle-
         * input thread stays free to service a Ctrl+W WiFi-setup
         * detour the whole time this blocks on the main thread. */
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
        ui_add_errorf("socket() failed: %d", SOCK_LAST_ERROR());
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

    /* See CONN_TIMEOUT_SECONDS above - this is what turns "network died
     * silently mid-session" into an eventual, detectable read failure
     * instead of an indefinite hang. */
    set_socket_timeout(sock);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        ui_add_error("wolfSSL_new failed");
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
    hw_oled_draw_text(oled_fd, 0, "SecureLink Bravo");
    hw_oled_draw_text(oled_fd, 1, "Connected");
    hw_oled_display(oled_fd);

    /* Stop the idle-input thread before run_symmetric_session() starts
     * its own reader on the same input_win, and resume it immediately
     * after - see ui.h's "IDLE INPUT" comment. These two calls must
     * bracket every run_symmetric_session() call exactly like this. */
    ui_stop_idle_input();
    result = run_symmetric_session(ssl, sock, hw_fd, oled_fd, "Alpha");
    ui_start_idle_input();

    hw_oled_draw_text(oled_fd, 0, "SecureLink Bravo");
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

#ifndef _WIN32
/* How long to wait for cloud-init's "boot-finished" marker before giving
 * up and drawing the splash anyway - bounded for the same reason every
 * other boot-time wait in this project is (SPLASH_MAX_WAIT_MS,
 * CONNECT_TIMEOUT_SECONDS, ...): "boots and works with zero manual
 * steps" has to hold even if cloud-init itself is unusually slow or
 * genuinely stuck this boot - a device that refuses to ever show its
 * UI because of someone ELSE's subsystem is exactly the kind of silent,
 * unrecoverable wait this project has repeatedly found and fixed. In
 * the ordinary case this returns almost immediately - by the time this
 * service's own After= chain (network-online.target, tailscaled,
 * fix-console-fb) has been satisfied, cloud-init has virtually always
 * already finished. */
#define CLOUD_INIT_WAIT_MAX_MS 15000
#define CLOUD_INIT_WAIT_POLL_MS 250

/* REAL BUG FOUND AND FIXED (2026-08-23), direct user report from a hard
 * unplug/replug power cycle: the boot sequence visibly "overlapped onto
 * the banner" - cloud-init's final stage (cloud-final.service) writes
 * plain text status directly to this same physical console (tty1) as
 * part of its own boot-time completion sequence, and if that happens
 * AFTER show_splash() (inside ui_init() below) has already put ncurses
 * in charge of the screen, those stray writes land on top of ncurses'
 * own screen buffer and visibly corrupt the splash - this project found
 * and documented the exact same underlying cause once already (see
 * securelink-alpha.service's own header comment, "REAL BUG FOUND VIA
 * LIVE TESTING" / cloud-init.target), but the fix attempted there
 * (After=cloud-init.target on the systemd unit) created a genuine
 * ordering cycle and had to be reverted - confirmed again here:
 * cloud-init.target AND cloud-final.service both carry
 * After=multi-user.target, while this unit's own WantedBy=multi-user.
 * target implicitly orders it BEFORE multi-user.target, so depending on
 * either one at the systemd level is a cycle no matter which is picked.
 *
 * Solved differently this time - entirely inside the application, no
 * systemd ordering involved at all, so there's no cycle to hit: wait,
 * bounded, for cloud-init's own standard "I am completely done"
 * sentinel file (the same one `cloud-init status --wait` itself polls
 * for) before ever calling ui_init() below. This runs once, this early,
 * specifically because everything before this point (arg parsing, TCP/
 * TLS setup, wolfSSL_CTX_new()) either exits immediately on failure or
 * doesn't touch the console at all - the only thing actually at risk of
 * corruption is the ncurses screen ui_init() is about to create, so
 * that's the one place this wait needs to guard. */
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

    /* REAL BUG FOUND AND FIXED (2026-08-23): ui_init()/ui_start_idle_input()
     * used to run much later, only after certificate/key/CA loading
     * (including load_private_key() below, which can call
     * keyshare_reconstruct() - a retry loop with NO timeout by design,
     * see keyshare.c) had already fully succeeded. That meant if this
     * device had no network path to its peer at boot at all - e.g. it's
     * in range of only an unrecognized WiFi network NetworkManager won't
     * auto-join, a real field scenario the user hit directly - the whole
     * boot sequence stalled forever with no UI, no WiFi-setup screen, no
     * way for anyone to intervene at all. Moved up here specifically so
     * the idle-input thread (Ctrl+W/WiFi setup, see ui.h's "IDLE INPUT"
     * comment) is ALREADY running while load_private_key() blocks on the
     * main thread below - a real network problem can now actually be
     * fixed from the touchscreen/keyboard instead of requiring a silent,
     * unrecoverable wait. Everything from here on goes through
     * ui_add_error()/ui_add_history() instead of fprintf/printf, same
     * "don't corrupt the ncurses screen" reasoning this file already
     * documented below - it just starts earlier now. The original
     * "nothing printed here includes a filesystem path" security property
     * is unaffected either way: none of these messages ever included a
     * raw path value, before or after this move. */
#ifndef _WIN32
    wait_for_cloud_init_boot_finished();
#endif
    /* 2026-08-23 (direct request): capitalized "Alpha"/"Bravo"
     * consistently everywhere either name is displayed - the banner,
     * message history ("Alpha: ..."/"Bravo: ..."), and the status bar
     * ("Connected to Bravo") all derive from this one literal, so
     * capitalizing it here (and the matching literal in
     * run_symmetric_session()'s call above) is the single source of
     * truth for every other display site. ui_init() also infers this
     * device's OWN identity from this same string (see its own
     * comment) - deliberately still just one argument, not two,
     * since self and peer are always exactly the other one of these
     * two literal names in this project's fixed two-device
     * architecture. */
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
    /* Deliberately NOT calling keyshare_stop_listener() here - see its
     * doc comment in keyshare.h for the real deadlock this caused the
     * first time around. The listener stays up for this process's
     * whole lifetime, so the peer can fetch its own share from THIS
     * device at any later point too, including after its own
     * independent reboot. */

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

    /* Restore the "about to connect" status now that credential loading
     * (which may have taken a while, or needed a WiFi-setup detour via
     * the idle-input thread started above) has actually finished -
     * ui_init() shows a generic version of this automatically at startup,
     * overwritten by "Loading credentials..." above; this puts the
     * accurate message back now that loading is done. */
    ui_set_status("Connecting to alpha...");

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
    ui_set_link_state(0);

    /* Case OLED (no-op on non-Linux / hardware-absent - see hw_oled.h),
     * opened once here and kept open for the whole reconnect loop, same
     * "physical device, own lifecycle" reasoning as hw_fd above. Client-
     * side OLED is new as of the two-way redesign - previously only the
     * server had one wired up. */
    oled_fd = hw_oled_open();
    ui_set_oled_fd(oled_fd); /* one-time wiring so ui.c's touch thread
        can periodically refresh background network metrics below
        session.c/here's own role/status lines - see ui.h. */
    hw_oled_draw_text(oled_fd, 0, "SecureLink Bravo");
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
    ui_stop_idle_input();
    ui_shutdown();

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
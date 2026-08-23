#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyshare.h"
#include "aes128.h"

/* keyshare_decrypt_private_key - deliberately defined here, OUTSIDE
 * the #ifdef __linux__ split below, since it's pure AES-128-CTR
 * decryption with zero platform-specific dependency (unlike
 * keyshare_reconstruct()/keyshare_stop_listener(), which genuinely
 * need fork()/sockets/pthread and stay Linux-only). Keeping this one
 * function portable is what let this exact round-trip get verified
 * on the dev machine before ever touching real Pi hardware - see
 * TESTING.md. */
long keyshare_decrypt_private_key(const char *encrypted_key_path,
                                   const uint8_t key[KEYSHARE_LEN],
                                   uint8_t *out_buf, size_t out_buf_size)
{
    FILE *fp;
    long file_size;
    size_t n;
    uint8_t round_key[AES128_ROUND_KEY_SIZE];
    uint8_t zero_counter[16];

    fp = fopen(encrypted_key_path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    file_size = ftell(fp);
    if (file_size < 0 || (size_t)file_size > out_buf_size) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    n = fread(out_buf, 1, (size_t)file_size, fp);
    fclose(fp);
    if (n != (size_t)file_size) {
        return -1;
    }

    /* Fixed all-zero counter is safe here specifically because K is
     * single-use: it exists to encrypt exactly this one file, exactly
     * once, ever - see keyshare.h's decrypt doc comment and the setup
     * tool for the same reasoning stated at the point K is generated. */
    memset(zero_counter, 0, sizeof(zero_counter));
    aes128_key_expansion(key, round_key);
    aes128_ctr_xcrypt(round_key, zero_counter, out_buf, out_buf, (size_t)file_size);
    memset(round_key, 0, sizeof(round_key));

    return file_size;
}

#ifdef __linux__

#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BACKOFF_INITIAL_SECONDS 1
#define BACKOFF_MAX_SECONDS     30
#define LISTENER_POLL_MS        500 /* how often accept() re-checks
                                        should_stop between connections */

/* --- run_tailscale(): fork()+execvp() the tailscale CLI, never a
 * shell - same discipline as wifi.c's run_nmcli(), for the same
 * reason (an SSID/password there, a Tailscale hostname/IP here, are
 * both untrusted-ish input worth not handing to a shell). --- */
static int run_tailscale(char *const argv[], char *out_buf, size_t out_buf_size)
{
    int pipefd[2];
    pid_t pid;
    int status;
    size_t have = 0;

    if (out_buf != NULL && out_buf_size > 0) {
        out_buf[0] = '\0';
    }
    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp("tailscale", argv);
        _exit(127);
    }
    close(pipefd[1]);
    if (out_buf != NULL && out_buf_size > 0) {
        for (;;) {
            ssize_t n = read(pipefd[0], out_buf + have, out_buf_size - 1 - have);
            if (n <= 0) {
                break;
            }
            have += (size_t)n;
            if (have >= out_buf_size - 1) {
                break;
            }
        }
        out_buf[have] = '\0';
    } else {
        char discard[128];
        while (read(pipefd[0], discard, sizeof(discard)) > 0) { }
    }
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

/* get_own_tailscale_ip - `tailscale ip -4`, trimmed. This is what the
 * share-listener binds to, deliberately never INADDR_ANY - a socket
 * bound only to the Tailscale IP is unreachable from anywhere except
 * the tailnet, regardless of what firewall rules do or don't exist,
 * matching the design note's "bound to the Tailscale interface only,
 * not the public internet" requirement structurally, not by policy. */
static int get_own_tailscale_ip(char *out_ip, size_t out_ip_size)
{
    char buf[128];
    char *argv[] = { (char *)"tailscale", (char *)"ip", (char *)"-4", NULL };
    size_t len;

    if (run_tailscale(argv, buf, sizeof(buf)) != 0) {
        return -1;
    }
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                        buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }
    if (len == 0 || len >= out_ip_size) {
        return -1;
    }
    memcpy(out_ip, buf, len + 1);
    return 0;
}

/* verify_peer_identity - `tailscale whois <ip>`, checked against a
 * confirmed-real output format (see TESTING.md): a line
 * "  Name:          <hostname>.<tailnet-suffix>" - matched against
 * expected_hostname as either an exact match or the short-name
 * portion before the first '.', so this doesn't need to know this
 * tailnet's own MagicDNS suffix. Returns 1 if it matches, 0 if it
 * doesn't (including "peer not found", ip's own exit-1 case), -1 on
 * a local error running the CLI itself. */
static int verify_peer_identity(const char *ip, const char *expected_hostname)
{
    char buf[1024];
    char *argv[] = { (char *)"tailscale", (char *)"whois", (char *)ip, NULL };
    char *line;
    char *saveptr = NULL;
    int rc;

    rc = run_tailscale(argv, buf, sizeof(buf));
    if (rc < 0) {
        return -1;
    }
    if (rc != 0) {
        return 0; /* "peer not found" or similar - not a match, not a
                      local error either */
    }

    line = strtok_r(buf, "\n", &saveptr);
    while (line != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (strncmp(p, "Name:", 5) == 0) {
            char *name = p + 5;
            size_t expected_len = strlen(expected_hostname);

            while (*name == ' ' || *name == '\t') {
                name++;
            }
            if (strncmp(name, expected_hostname, expected_len) == 0 &&
                (name[expected_len] == '.' || name[expected_len] == '\0' ||
                 name[expected_len] == '\r' || name[expected_len] == '\n')) {
                return 1;
            }
            return 0;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return 0;
}

static int read_file_exact(const char *path, uint8_t *buf, size_t len)
{
    FILE *fp = fopen(path, "rb");
    size_t n;

    if (fp == NULL) {
        return -1;
    }
    n = fread(buf, 1, len, fp);
    fclose(fp);
    return (n == len) ? 0 : -1;
}

static void xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/* --- Listener: serves this device's custody-share for the peer,
 * once the connecting peer's Tailscale identity is verified. --- */

typedef struct {
    char my_custody_share_path[512];
    char peer_expected_hostname[256];
    int listen_port;
    int listen_sock;
    volatile int should_stop;
} listener_state;

static listener_state g_listener;
static pthread_t g_listener_thread;
static volatile int g_listener_running = 0;

static void *listener_thread_main(void *arg)
{
    listener_state *st = (listener_state *)arg;

    for (;;) {
        struct pollfd pfd;
        int pr;
        int client_sock;
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);

        if (st->should_stop) {
            break;
        }

        pfd.fd = st->listen_sock;
        pfd.events = POLLIN;
        pr = poll(&pfd, 1, LISTENER_POLL_MS);
        if (pr <= 0) {
            continue; /* timeout or transient error - loop back to the
                          should_stop check */
        }

        client_sock = accept(st->listen_sock, (struct sockaddr *)&peer_addr,
                              &peer_len);
        if (client_sock < 0) {
            continue;
        }

        {
            char ip_str[INET_ADDRSTRLEN];
            uint8_t share[KEYSHARE_LEN];

            inet_ntop(AF_INET, &peer_addr.sin_addr, ip_str, sizeof(ip_str));

            /* Only ever serve the share to a connection whose source
             * IP's Tailscale identity is confirmed to be the specific
             * expected peer - never "anyone who can reach this port",
             * which a listener bound to the Tailscale interface alone
             * doesn't structurally guarantee (other tailnet members
             * could still reach it). */
            if (verify_peer_identity(ip_str, st->peer_expected_hostname) == 1 &&
                read_file_exact(st->my_custody_share_path, share,
                                 sizeof(share)) == 0) {
                write(client_sock, share, sizeof(share));
                memset(share, 0, sizeof(share));
            }
            /* Anything else (identity mismatch, missing local file):
             * close without sending anything - the requester's own
             * retry-with-backoff loop handles a silently-refused
             * attempt the same as a transient network failure. */
        }
        close(client_sock);
    }

    close(st->listen_sock);
    return NULL;
}

static int start_listener(const char *my_custody_share_path,
                           const char *peer_expected_hostname,
                           int listen_port)
{
    char own_ip[128];
    struct sockaddr_in addr;
    int sock;
    int opt = 1;

    if (get_own_tailscale_ip(own_ip, sizeof(own_ip)) != 0) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, own_ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }
    if (listen(sock, 1) != 0) {
        close(sock);
        return -1;
    }

    snprintf(g_listener.my_custody_share_path,
             sizeof(g_listener.my_custody_share_path), "%s",
             my_custody_share_path);
    snprintf(g_listener.peer_expected_hostname,
             sizeof(g_listener.peer_expected_hostname), "%s",
             peer_expected_hostname);
    g_listener.listen_port = listen_port;
    g_listener.listen_sock = sock;
    g_listener.should_stop = 0;

    if (pthread_create(&g_listener_thread, NULL, listener_thread_main,
                        &g_listener) != 0) {
        close(sock);
        return -1;
    }
    g_listener_running = 1;
    return 0;
}

void keyshare_stop_listener(void)
{
    if (!g_listener_running) {
        return;
    }
    g_listener.should_stop = 1;
    pthread_join(g_listener_thread, NULL);
    g_listener_running = 0;
}

int keyshare_get_own_tailscale_ip(char *out_ip, size_t out_ip_size)
{
    return get_own_tailscale_ip(out_ip, out_ip_size);
}

/* --- Fetching this device's own remote_share from the peer --- */

static int fetch_remote_share(const char *peer_ip, int peer_port,
                               uint8_t out_share[KEYSHARE_LEN])
{
    struct sockaddr_in addr;
    int sock;
    ssize_t total = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)peer_port);
    if (inet_pton(AF_INET, peer_ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    while (total < (ssize_t)KEYSHARE_LEN) {
        ssize_t n = read(sock, out_share + total, KEYSHARE_LEN - total);
        if (n <= 0) {
            close(sock);
            return -1;
        }
        total += n;
    }
    close(sock);
    return 0;
}

int keyshare_reconstruct(const char *local_share_path,
                          const char *peer_tailscale_ip,
                          const char *peer_expected_hostname,
                          const char *my_custody_share_path,
                          int listen_port,
                          uint8_t out_key[KEYSHARE_LEN])
{
    uint8_t local_share[KEYSHARE_LEN];
    uint8_t remote_share[KEYSHARE_LEN];
    int backoff = BACKOFF_INITIAL_SECONDS;

    if (read_file_exact(local_share_path, local_share, sizeof(local_share)) != 0) {
        return -1; /* missing local file - retrying won't fix this */
    }

    if (start_listener(my_custody_share_path, peer_expected_hostname,
                        listen_port) != 0) {
        return -1;
    }

    for (;;) {
        int identity_ok = verify_peer_identity(peer_tailscale_ip,
                                                peer_expected_hostname);
        if (identity_ok == 1 &&
            fetch_remote_share(peer_tailscale_ip, listen_port,
                                remote_share) == 0) {
            break;
        }
        sleep((unsigned int)backoff);
        backoff *= 2;
        if (backoff > BACKOFF_MAX_SECONDS) {
            backoff = BACKOFF_MAX_SECONDS;
        }
    }

    xor_bytes(out_key, local_share, remote_share, KEYSHARE_LEN);
    memset(local_share, 0, sizeof(local_share));
    memset(remote_share, 0, sizeof(remote_share));
    return 0;
}

#else /* !__linux__ */

/* No Tailscale CLI plumbing on this project's Windows dev machine in
 * the way this module needs it (fork()+execvp(), raw sockets bound
 * to a specific interface) - the mutual key-share flow is a Linux/
 * real-hardware-only feature. These stubs exist so callers can link
 * on either platform without #ifdef guards at every call site,
 * matching wifi.h/touch.h's established precedent. Dev-machine
 * testing continues to use a plain -k PEM file path instead. */

int keyshare_reconstruct(const char *local_share_path,
                          const char *peer_tailscale_ip,
                          const char *peer_expected_hostname,
                          const char *my_custody_share_path,
                          int listen_port,
                          uint8_t out_key[KEYSHARE_LEN])
{
    (void)local_share_path;
    (void)peer_tailscale_ip;
    (void)peer_expected_hostname;
    (void)my_custody_share_path;
    (void)listen_port;
    (void)out_key;
    return -1;
}

void keyshare_stop_listener(void)
{
}

int keyshare_get_own_tailscale_ip(char *out_ip, size_t out_ip_size)
{
    (void)out_ip;
    (void)out_ip_size;
    return -1;
}

#endif /* __linux__ */

#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Portability shim - same as client.c/server.c. */
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
    #include <netdb.h>
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

#include "message.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433

/* --- Phase 1 design decisions, documented here where they're used ---
 * (see docs/BENCHMARK_WRITEUP.md for the write-up itself, which needs
 * real numbers from an actual run filled in - this file only produces
 * the numbers, it can't write the write-up's conclusion for you). */

/* 10,000+ per the build log's own requirement. */
#define HANDSHAKE_ITERATIONS 10000

/* Short payload: one realistic chat-style line. */
#define SMALL_PAYLOAD "Hey, you free to grab dinner tonight?"
#define SMALL_PAYLOAD_ITERATIONS 2000

/* Larger payload: "a few KB", well under DD_MAX_BODY_LEN (64 KiB).
 * 4096 bytes chosen as a clean, round few-KB size. */
#define LARGE_PAYLOAD_SIZE 4096
#define LARGE_PAYLOAD_ITERATIONS 500

static double elapsed_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0
         + (end->tv_nsec - start->tv_nsec) / 1e6;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <client_cert.pem> -k <client_key.pem> "
        "-A <ca_cert.pem> [-h <host>] [-p <port>]\n"
        "Run against an already-running server.exe - same cert/key/CA\n"
        "args as client.c.\n",
        prog_name);
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

/* n is the number of VALID entries actually in samples - callers that
 * bail out early (e.g. a dead connection mid-benchmark) pass however
 * many iterations actually completed, not the originally requested
 * count, so this never reads past what was really measured. */
static void print_stats(const char *label, double *samples, int n)
{
    double min, max, median, sum = 0.0;
    int i;

    if (n <= 0) {
        printf("%-28s (no samples collected)\n", label);
        return;
    }

    qsort(samples, (size_t)n, sizeof(double), cmp_double);
    min = samples[0];
    max = samples[n - 1];
    median = samples[n / 2];
    for (i = 0; i < n; i++) {
        sum += samples[i];
    }

    printf("%-28s n=%-6d min=%9.4f ms  median=%9.4f ms  "
           "mean=%9.4f ms  max=%9.4f ms\n",
           label, n, min, median, sum / n, max);
}

/* Open a fresh TCP connection to host:port. Uses getaddrinfo() rather than
 * inet_pton() - matches client.c as of commit ba6ab0d, which switched for
 * exactly this reason: inet_pton() only parses numeric IP text, so it
 * flatly rejects a Tailscale MagicDNS hostname with no lookup attempted
 * at all. This benchmark needs to work against whatever addressing
 * scheme client.c ends up using once Week 3 Day 3's second device
 * exists, so it has to handle both a raw IP and a hostname the same way
 * client.c does. Returns SOCKET_INVALID on failure. */
static socket_t open_tcp_connection(const char *host, int port)
{
    socket_t sock;
    struct sockaddr_in server_addr;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char port_str[6];
    int gai_rc;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCKET_INVALID) {
        fprintf(stderr, "socket() failed: %d\n", SOCK_LAST_ERROR());
        return SOCKET_INVALID;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* project is IPv4-only throughout */
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);

    gai_rc = getaddrinfo(host, port_str, &hints, &res);
    if (gai_rc != 0) {
        fprintf(stderr, "getaddrinfo failed for host '%s': %s\n",
                host, gai_strerror(gai_rc));
        CLOSE_SOCKET(sock);
        return SOCKET_INVALID;
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
        return SOCKET_INVALID;
    }

    if (connect(sock, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) == SOCKET_ERR_RET) {
        fprintf(stderr, "connect() failed: %d\n", SOCK_LAST_ERROR());
        CLOSE_SOCKET(sock);
        return SOCKET_INVALID;
    }

    return sock;
}

/*
 * run_handshake_benchmark - Phase 3's per-iteration handshake loop.
 * "One handshake iteration" = fresh TCP connect -> full mTLS handshake,
 * timed from just before wolfSSL_new() to just after wolfSSL_connect()
 * returns. The DISCONNECT send + close after that is NOT timed - it's
 * only there to keep the single-threaded server (see server.c: one
 * connection at a time) responsive for the next iteration instead of
 * sitting on a 30s read timeout for a connection that's just going to be
 * abandoned anyway.
 */
static void run_handshake_benchmark(WOLFSSL_CTX *ctx, const char *host,
                                     int port, int iterations)
{
    double *samples = malloc(sizeof(double) * (size_t)iterations);
    int i;
    int valid = 0;    /* count of samples[] entries actually written -
                        * only successful handshakes, see below */
    int failures = 0;

    if (samples == NULL) {
        fprintf(stderr, "run_handshake_benchmark: out of memory\n");
        return;
    }

    printf("Running handshake benchmark (%d iterations)...\n", iterations);

    for (i = 0; i < iterations; i++) {
        struct timespec t0, t1;
        socket_t sock;
        WOLFSSL *ssl;
        int rc;
        double sample_ms;

        sock = open_tcp_connection(host, port);
        if (sock == SOCKET_INVALID) {
            fprintf(stderr, "iteration %d: connect failed, aborting\n", i);
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &t0);
        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "iteration %d: wolfSSL_new failed\n", i);
            CLOSE_SOCKET(sock);
            break;
        }
        wolfSSL_set_fd(ssl, (int)sock);
        /* Needed because the (untimed) block below calls dd_session_init(),
         * which exports keying material after the handshake completes -
         * without this, wolfSSL would have already freed the temporary
         * arrays that export needs. */
        wolfSSL_KeepArrays(ssl);
        rc = wolfSSL_connect(ssl);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        sample_ms = elapsed_ms(&t0, &t1);

        if (rc != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, rc);
            char errbuf[80];
            fprintf(stderr, "iteration %d: handshake failed: %s\n", i,
                    wolfSSL_ERR_error_string(err, errbuf));
            /* Do NOT record sample_ms below - a failed attempt's timing
             * describes how long it took to error out, not how long a
             * real handshake takes, and mixing the two into the same
             * stats with no visible failure count would make a bad
             * min/median/max silently look like normal variance instead
             * of what it actually is. failures is reported explicitly
             * below instead. */
            failures++;
        } else {
            dd_session_state state;
            samples[valid++] = sample_ms;
            if (dd_session_init(ssl, &state) == 0) {
                uint8_t buf[DD_HEADER_SIZE + DD_HMAC_SIZE];
                int n = dd_serialize_message(&state, DD_MSG_DISCONNECT,
                                              NULL, 0, buf, sizeof(buf));
                if (n > 0) {
                    wolfSSL_write(ssl, buf, n);
                }
            }
        }

        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
    }

    if (failures > 0) {
        fprintf(stderr,
            "run_handshake_benchmark: %d of %d attempted handshakes "
            "failed and were excluded from the stats below (see the "
            "per-iteration errors above)\n", failures, i);
    }
    print_stats("Handshake (connect+TLS)", samples, valid);
    free(samples);
}

/*
 * run_throughput_benchmark - connect and handshake ONCE, then send
 * `iterations` TEXT_MESSAGEs of `payload_len` bytes over that one
 * persistent connection, timing each round trip: send -> wait for the
 * server's "ack: " reply (server.c echoes every TEXT_MESSAGE this way).
 */
static void run_throughput_benchmark(WOLFSSL_CTX *ctx, const char *host,
                                      int port, const char *label,
                                      size_t payload_len, int iterations)
{
    socket_t sock;
    WOLFSSL *ssl = NULL;
    int rc;
    dd_session_state state;
    uint8_t *payload = NULL;
    uint8_t *send_buf = NULL;
    uint8_t *recv_buf = NULL;
    double *samples = NULL;
    size_t have = 0;
    int completed = 0;

    sock = open_tcp_connection(host, port);
    if (sock == SOCKET_INVALID) {
        return;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "run_throughput_benchmark: wolfSSL_new failed\n");
        CLOSE_SOCKET(sock);
        return;
    }
    wolfSSL_set_fd(ssl, (int)sock);
    /* Same requirement as run_handshake_benchmark() above: the upcoming
     * dd_session_init() call needs wolfSSL's handshake arrays to still be
     * around after wolfSSL_connect() returns, which only happens if this
     * is called before the handshake, not after. Missing here is exactly
     * the Day 2 wolfSSL_export_keying_material-fails-silently bug. */
    wolfSSL_KeepArrays(ssl);

    rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr, "run_throughput_benchmark: handshake failed: %s\n",
                wolfSSL_ERR_error_string(err, errbuf));
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return;
    }

    if (dd_session_init(ssl, &state) != 0) {
        fprintf(stderr, "run_throughput_benchmark: dd_session_init failed\n");
        goto cleanup;
    }

    payload = malloc(payload_len > 0 ? payload_len : 1);
    send_buf = malloc(DD_MAX_MSG_SIZE);
    recv_buf = malloc(DD_MAX_MSG_SIZE);
    samples = malloc(sizeof(double) * (size_t)iterations);
    if (payload == NULL || send_buf == NULL || recv_buf == NULL ||
        samples == NULL) {
        fprintf(stderr, "run_throughput_benchmark: out of memory\n");
        goto cleanup;
    }
    memset(payload, 'x', payload_len); /* content doesn't affect timing */

    printf("Running throughput benchmark: %s (%zu bytes, %d iterations)...\n",
           label, payload_len, iterations);

    for (completed = 0; completed < iterations; completed++) {
        struct timespec t0, t1;
        int total;
        int broke_on_error = 0;

        clock_gettime(CLOCK_MONOTONIC, &t0);

        total = dd_serialize_message(&state, DD_MSG_TEXT_MESSAGE, payload,
                                      (uint32_t)payload_len,
                                      send_buf, DD_MAX_MSG_SIZE);
        if (total < 0) {
            fprintf(stderr, "iteration %d: serialize failed\n", completed);
            break;
        }
        rc = wolfSSL_write(ssl, send_buf, total);
        if (rc != total) {
            fprintf(stderr, "iteration %d: write failed\n", completed);
            break;
        }

        /* Wait for the server's reply - same streaming-parse shape as
         * client.c's receive_one_message(), inlined here since this is
         * the only place in this file that needs it. */
        for (;;) {
            dd_parsed_message msg;
            size_t consumed = 0;
            dd_parse_result pr = dd_try_parse_message(&state, recv_buf,
                                                        have, &msg,
                                                        &consumed);
            if (pr == DD_PARSE_OK) {
                memmove(recv_buf, recv_buf + consumed, have - consumed);
                have -= consumed;
                break;
            }
            if (pr == DD_PARSE_REJECTED) {
                fprintf(stderr, "iteration %d: rejected reply\n", completed);
                broke_on_error = 1;
                break;
            }
            {
                int n = wolfSSL_read(ssl, (char *)(recv_buf + have),
                                      (int)(DD_MAX_MSG_SIZE - have));
                if (n <= 0) {
                    fprintf(stderr, "iteration %d: read failed\n", completed);
                    broke_on_error = 1;
                    break;
                }
                have += (size_t)n;
            }
        }
        if (broke_on_error) {
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples[completed] = elapsed_ms(&t0, &t1);
    }

    print_stats(label, samples, completed);

    {
        uint8_t dbuf[DD_HEADER_SIZE + DD_HMAC_SIZE];
        int n = dd_serialize_message(&state, DD_MSG_DISCONNECT, NULL, 0,
                                      dbuf, sizeof(dbuf));
        if (n > 0) {
            wolfSSL_write(ssl, dbuf, n);
        }
    }

cleanup:
    free(payload);
    free(send_buf);
    free(recv_buf);
    free(samples);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    CLOSE_SOCKET(sock);
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

    parse_args(argc, argv, &host, &port, &cert_path, &key_path, &ca_path);
    if (cert_path == NULL || key_path == NULL || ca_path == NULL) {
        print_usage(argv[0]);
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

    if (wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load cert/key/CA from %s / %s / %s\n",
                cert_path, key_path, ca_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    printf("DeadDrop benchmark - DEV-MACHINE NUMBERS ONLY, not final\n"
           "performance. Re-run on the Pi once it's up in Week 4.\n\n");

    run_handshake_benchmark(ctx, host, port, HANDSHAKE_ITERATIONS);
    printf("\n");
    run_throughput_benchmark(ctx, host, port, "Throughput (small payload)",
                              strlen(SMALL_PAYLOAD), SMALL_PAYLOAD_ITERATIONS);
    printf("\n");
    run_throughput_benchmark(ctx, host, port, "Throughput (large payload)",
                              LARGE_PAYLOAD_SIZE, LARGE_PAYLOAD_ITERATIONS);

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
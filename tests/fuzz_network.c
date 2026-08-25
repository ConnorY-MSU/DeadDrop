#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Portability shim - same as client.c/server.c/benchmark.c. */
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

/*
 * Network-level fuzz test - Week 3 Day 5, added on top of the in-process
 * fuzz_message.c harness after an explicit request to make testing more
 * intensive. This is a genuinely different test class, not just more of
 * the same: fuzz_message.c calls dd_try_parse_message() directly with a
 * pre-assembled buffer, which can never exercise how the REAL server
 * process behaves when malformed bytes arrive over an actual socket -
 * TCP fragmentation, wolfSSL_read()'s own buffering, the accept loop,
 * and receive_one_message()'s accumulate-until-complete logic are all
 * structurally untested by an in-process call. This harness connects to
 * an already-running server.exe for real, completes a genuine mTLS
 * handshake (so the fuzzing targets the post-handshake application
 * protocol layer specifically, not wolfSSL's own handshake parser, which
 * is out of this project's scope to fuzz), then sends malformed
 * post-handshake payloads and confirms the server never crashes.
 *
 * Must be run against a server.exe built with -fsanitize=address
 * -fsanitize=undefined for this to mean anything - a crash in the SERVER
 * process shows up as the server's own stderr/log output getting an ASan
 * report and the server process disappearing; this client process
 * itself is not expected to crash (a real server correctly rejecting
 * garbage should just close the connection cleanly on this end).
 *
 * Cost note: unlike fuzz_message.c's million-plus in-process iterations,
 * each iteration here costs a full fresh TCP+mTLS handshake (per Week 3
 * Day 4's benchmark, ~12-14ms each on this dev machine) - so this uses a
 * much smaller iteration count (thousands, not millions), which is the
 * right tradeoff for what this test class is actually for: proving the
 * real deployed path is robust, not exhaustively searching the input
 * space the way the cheap in-process fuzzer already does.
 */

#define ITERATIONS 3000
#define MAX_PAYLOAD 4096

static const char *host = "127.0.0.1";
static int port = 4433;
static const char *cert_path = NULL;
static const char *key_path = NULL;
static const char *ca_path = NULL;

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
        "Usage: %s -c <client_cert.pem> -k <client_key.pem> "
        "-A <ca_cert.pem> [-h <host>] [-p <port>]\n"
        "Sends malformed post-handshake payloads to an already-running\n"
        "server.exe and confirms it never crashes. Check the server's own\n"
        "log/exit status separately after this finishes.\n",
        prog_name);
}

static void parse_args(int argc, char *argv[])
{
    int i;
    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0) {
            cert_path = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "-A") == 0) {
            ca_path = argv[++i];
        }
    }
}

/* Same getaddrinfo()-based connect as client.c/benchmark.c - see
 * client.c's own comment (commit ba6ab0d) for why this isn't inet_pton(). */
/* Short client-side timeout, deliberately much shorter than server.c's
 * own 30-second SO_RCVTIMEO. Without this, a fuzz payload that happens
 * to be shorter than a complete message (quite likely across thousands
 * of random-length payloads) makes the server correctly block in
 * wolfSSL_read() waiting for the rest of a message that this harness
 * never sends (it only writes once per iteration) - and this client
 * then blocks right back waiting for a reply, so the pair only resolves
 * once the SERVER's 30-second timeout eventually fires. Hit this for
 * real: 3000 iterations was still only 219 connections deep after
 * roughly 15-20 minutes before this fix, not a crash or a hang, just a
 * harness that could cost up to 30 real seconds per "incomplete-shaped"
 * payload. This isn't testing anything a shorter timeout wouldn't also
 * catch - the thing being proven (server doesn't crash) doesn't need
 * this harness to wait as long as a real, patient peer would. */
#define FUZZ_CLIENT_TIMEOUT_SECONDS 2

static void set_socket_timeout(socket_t s)
{
#ifdef _WIN32
    DWORD timeout_ms = FUZZ_CLIENT_TIMEOUT_SECONDS * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = FUZZ_CLIENT_TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static socket_t open_tcp_connection(void)
{
    socket_t sock;
    struct sockaddr_in server_addr;
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[6];
    int gai_rc;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCKET_INVALID) {
        return SOCKET_INVALID;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    gai_rc = getaddrinfo(host, port_str, &hints, &res);
    if (gai_rc != 0) {
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
        CLOSE_SOCKET(sock);
        return SOCKET_INVALID;
    }

    if (connect(sock, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) == SOCKET_ERR_RET) {
        CLOSE_SOCKET(sock);
        return SOCKET_INVALID;
    }

    set_socket_timeout(sock);
    return sock;
}

/* One iteration: connect, real mTLS handshake, send ONE malformed
 * post-handshake payload, see what happens, clean up. One malformed
 * payload per connection is deliberate, not a limitation worked around -
 * server.c's own policy is that any single rejected message is fatal to
 * the whole connection (see TESTING.md's Week 3 Day 2 section), so a
 * second payload on the same connection would never actually reach the
 * parser again after the first one closes it. */
static int run_one_iteration(WOLFSSL_CTX *ctx, int iteration,
                              long *handshake_failures,
                              long *server_closed_cleanly,
                              long *write_failures)
{
    socket_t sock;
    WOLFSSL *ssl;
    int rc;
    uint8_t payload[MAX_PAYLOAD];
    size_t payload_len;
    int strategy;

    sock = open_tcp_connection();
    if (sock == SOCKET_INVALID) {
        fprintf(stderr, "iteration %d: connect failed\n", iteration);
        return -1;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        CLOSE_SOCKET(sock);
        return -1;
    }
    wolfSSL_set_fd(ssl, (int)sock);

    rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        /* Not itself a finding - a real network could always fail a
         * handshake for mundane reasons. Counted, not treated as fatal. */
        (*handshake_failures)++;
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return 0;
    }

    /* Build one malformed post-handshake payload. Several strategies,
     * chosen randomly each iteration - deliberately bypasses
     * dd_serialize_message() entirely, since the whole point is sending
     * bytes the real protocol layer never would, exactly what an actual
     * malicious or buggy peer might do on the wire. */
    strategy = rand() % 6;
    switch (strategy) {
        case 0: /* pure random, random length */
            payload_len = (size_t)(rand() % (MAX_PAYLOAD + 1));
            {
                size_t j;
                for (j = 0; j < payload_len; j++) {
                    payload[j] = (uint8_t)(rand() % 256);
                }
            }
            break;
        case 1: /* empty write (zero-length payload) */
            payload_len = 0;
            break;
        case 2: /* a well-formed-looking header claiming an absurd body_length,
                  * with no actual body/tag bytes following at all */
            memset(payload, 0, DD_HEADER_SIZE);
            payload[0] = DD_VERSION;
            payload[1] = DD_MSG_TEXT_MESSAGE;
            payload[8] = 0xFF; payload[9] = 0xFF;
            payload[10] = 0xFF; payload[11] = 0xFF; /* huge claimed length */
            payload_len = DD_HEADER_SIZE;
            break;
        case 3: /* a real header, real-looking but garbage HMAC tag, no body */
            memset(payload, 0, DD_HEADER_SIZE + DD_HMAC_SIZE);
            payload[0] = DD_VERSION;
            payload[1] = DD_MSG_PING;
            {
                size_t j;
                for (j = DD_HEADER_SIZE; j < DD_HEADER_SIZE + DD_HMAC_SIZE; j++) {
                    payload[j] = (uint8_t)(rand() % 256);
                }
            }
            payload_len = DD_HEADER_SIZE + DD_HMAC_SIZE;
            break;
        case 4: /* all-zero, a plausible minimum-size buffer */
            memset(payload, 0, DD_HEADER_SIZE + DD_HMAC_SIZE);
            payload_len = DD_HEADER_SIZE + DD_HMAC_SIZE;
            break;
        case 5:
        default: /* large random payload, near MAX_PAYLOAD */
            payload_len = (size_t)(MAX_PAYLOAD - (rand() % 64));
            {
                size_t j;
                for (j = 0; j < payload_len; j++) {
                    payload[j] = (uint8_t)(rand() % 256);
                }
            }
            break;
    }

    if (payload_len > 0) {
        rc = wolfSSL_write(ssl, payload, (int)payload_len);
        if (rc <= 0) {
            (*write_failures)++;
        }
    }

    /* See what the server does - a clean rejection should show up as
     * the connection closing (a read here returns <= 0). This process
     * (the fuzzer) is not expected to crash either way; the thing being
     * proven is that the SERVER process survives, which is confirmed
     * separately by the orchestrating script checking the server is
     * still running after all iterations complete. */
    {
        char reply_buf[16];
        rc = wolfSSL_read(ssl, reply_buf, sizeof(reply_buf));
        if (rc <= 0) {
            (*server_closed_cleanly)++;
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    CLOSE_SOCKET(sock);
    return 0;
}

int main(int argc, char *argv[])
{
    WOLFSSL_CTX *ctx = NULL;
    int rc;
    int i;
    long handshake_failures = 0, server_closed_cleanly = 0, write_failures = 0;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    parse_args(argc, argv);
    if (cert_path == NULL || key_path == NULL || ca_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    srand((unsigned)time(NULL));

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
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        return 1;
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load cert/key/CA\n");
        wolfSSL_CTX_free(ctx);
        return 1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    printf("Network-level fuzz test: %d iterations against %s:%d\n"
           "Each iteration is a fresh real mTLS connection + one malformed\n"
           "post-handshake payload. Confirm the server is still running\n"
           "(and its own log has no ASan/UBSan report) after this completes.\n\n",
           ITERATIONS, host, port);

    for (i = 0; i < ITERATIONS; i++) {
        run_one_iteration(ctx, i, &handshake_failures,
                           &server_closed_cleanly, &write_failures);
        if ((i + 1) % 250 == 0) {
            printf("  ... %d/%d iterations complete\n", i + 1, ITERATIONS);
            fflush(stdout);
        }
    }

    printf("\nhandshake_failures=%ld server_closed_cleanly=%ld "
           "write_failures=%ld\n",
           handshake_failures, server_closed_cleanly, write_failures);
    printf("\nNETWORK FUZZING COMPLETE - this process did not crash.\n"
           "Now go check the server's own process/log separately.\n");

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

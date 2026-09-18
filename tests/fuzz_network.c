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

/* Network-level fuzz test: real mTLS handshake to a running server.exe, then malformed post-handshake payloads; server must survive. See COMMENT_ARCHIVE.md. */

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

/* Same getaddrinfo()-based connect as client.c/benchmark.c. */
/* Short client-side timeout (much shorter than server.c's 30s SO_RCVTIMEO) so incomplete payloads don't wait 30s. See COMMENT_ARCHIVE.md. */
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

/* One iteration: connect, mTLS handshake, send ONE malformed payload, clean up (one per connection since server.c treats rejection as fatal - see TESTING.md). */
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
        /* Not itself a finding - a real network could always fail a handshake for mundane reasons; counted, not fatal. */
        (*handshake_failures)++;
        wolfSSL_free(ssl);
        CLOSE_SOCKET(sock);
        return 0;
    }

    /* Build one malformed post-handshake payload, chosen randomly; bypasses dd_serialize_message() on purpose. */
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
        case 2: /* a well-formed-looking header claiming an absurd body_length, with no body/tag bytes following */
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

    /* A clean rejection shows up as the connection closing (read <= 0); the SERVER surviving is confirmed separately by the orchestrating script. */
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

#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Host/port are generic, sensible defaults (loopback, this project's
 * standard port) - not tied to any one machine, so they're fine to keep
 * as defaults. Cert/key/CA paths are NOT: a hardcoded absolute path
 * only ever works on the machine it was typed on, so those are required
 * arguments with no default, same reasoning as server.c. */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433

#define CLIENT_MESSAGE "hello from client.c"

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

int main(int argc, char *argv[])
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int rc;

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

    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return 1;
    }

    rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed: %d\n", rc);
        WSACleanup();
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    rc = wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_certificate_file failed (rc=%d) for %s\n",
            rc, cert_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    rc = wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_use_PrivateKey_file failed (rc=%d) for %s\n",
            rc, key_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    rc = wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr,
            "wolfSSL_CTX_load_verify_locations failed (rc=%d) for %s\n",
            rc, ca_path);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    printf("wolfSSL initialized; cert/key/CA loaded from %s / %s / %s\n",
           cert_path, key_path, ca_path);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed for host '%s'\n", host);
        closesocket(sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    rc = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }
    printf("Connected to server.\n");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new failed\n");
        closesocket(sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    wolfSSL_set_fd(ssl, (int)sock);

    rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr, "Handshake failed: %s\n",
                wolfSSL_ERR_error_string(err, errbuf));
        wolfSSL_free(ssl);
        closesocket(sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }
    printf("mTLS handshake succeeded.\n");

    rc = wolfSSL_write(ssl, CLIENT_MESSAGE, (int)strlen(CLIENT_MESSAGE));
    if (rc <= 0) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr, "wolfSSL_write failed: %s\n",
                wolfSSL_ERR_error_string(err, errbuf));
    } else {
        printf("Sent: %s\n", CLIENT_MESSAGE);
    }

    wolfSSL_free(ssl);
    closesocket(sock);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    WSACleanup();

    return 0;
}

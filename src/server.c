#define WOLFSSL_USE_OPTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "revocation.h"

#define SERVER_PORT 4433
#define LISTEN_BACKLOG 1
#define READ_BUF_SIZE 256

#define SERIAL_BUF_SIZE 32

static int my_verify_callback(int preverify_ok, WOLFSSL_X509_STORE_CTX *store)
{
    WOLFSSL_X509 *cert;
    byte serial_bytes[SERIAL_BUF_SIZE];
    int serial_len = sizeof(serial_bytes);
    char serial_hex[SERIAL_BUF_SIZE * 2 + 1];
    int i;
    int rc;

    if (!preverify_ok) {
        fprintf(stderr,
            "Verify callback: standard cert-chain verification failed.\n");
        return 0;
    }

    cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if (cert == NULL) {
        fprintf(stderr, "Verify callback: no current cert available.\n");
        return 0;
    }

    rc = wolfSSL_X509_get_serial_number(cert, serial_bytes, &serial_len);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Verify callback: could not read serial number.\n");
        return 0;
    }

    if (serial_len <= 0 || (size_t)(serial_len * 2) >= sizeof(serial_hex)) {
        fprintf(stderr, "Verify callback: unexpected serial length (%d).\n",
                serial_len);
        return 0;
    }

    for (i = 0; i < serial_len; i++) {
        sprintf(&serial_hex[i * 2], "%02X", serial_bytes[i]);
    }
    serial_hex[serial_len * 2] = '\0';

    printf("Verify callback: checking serial %s against revocation list.\n",
           serial_hex);
    fflush(stdout);

    if (revocation_is_revoked(serial_hex)) {
        fprintf(stderr, "Verify callback: serial %s is REVOKED - rejecting.\n",
                serial_hex);
        return 0;
    }

    printf("Verify callback: serial %s not revoked, proceeding.\n", serial_hex);
    fflush(stdout);
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

int main(int argc, char *argv[])
{
    WSADATA wsa_data;
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    WOLFSSL_CTX *ctx = NULL;
    int rc;

    const char *cert_path = NULL;
    const char *key_path = NULL;
    const char *ca_path = NULL;
    const char *revoked_path = NULL;

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
    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return 1;
    }

    /* --- wolfSSL init + context --- */
    rc = wolfSSL_Init();
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed: %d\n", rc);
        WSACleanup();
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
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
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        my_verify_callback);

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
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
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    rc = listen(listen_sock, LISTEN_BACKLOG);
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        WSACleanup();
        return 1;
    }

    printf("Listening on port %d...\n", SERVER_PORT);
    fflush(stdout);

    for (;;) {
        SOCKET client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
            continue; 
        }
        printf("Raw TCP client connected.\n");
        fflush(stdout);

        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failed\n");
            closesocket(client_sock);
            continue;
        }

        wolfSSL_set_fd(ssl, (int)client_sock);

        rc = wolfSSL_accept(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, rc);
            char errbuf[80];
            fprintf(stderr, "Handshake failed: %s\n",
                    wolfSSL_ERR_error_string(err, errbuf));
        } else {
            printf("mTLS handshake succeeded.\n");
            fflush(stdout);

            char buf[READ_BUF_SIZE];
            int n = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("Client message: %s\n", buf);
                fflush(stdout);
            } else {
                int err = wolfSSL_get_error(ssl, n);
                char errbuf[80];
                fprintf(stderr, "wolfSSL_read failed: %s\n",
                        wolfSSL_ERR_error_string(err, errbuf));
            }
        }

        wolfSSL_free(ssl);
        closesocket(client_sock);
    }

    closesocket(listen_sock);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    revocation_free();
    WSACleanup();

    return 0;
}
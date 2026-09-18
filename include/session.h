#ifndef SESSION_H
#define SESSION_H

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Portable socket type - on 64-bit Windows, SOCKET is a 64-bit handle (UINT_PTR), not a plain int. See COMMENT_ARCHIVE.md. */
#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET socket_t;
#else
    typedef int socket_t;
#endif

/* session - shared two-way interactive session, used by both client.c and server.c after their mTLS handshake completes. See COMMENT_ARCHIVE.md. */

typedef enum {
    SESSION_USER_QUIT,    /* the local user explicitly quit (or stdin EOF) */
    SESSION_DISCONNECTED  /* connection ended any other way (peer disconnect, read/write failure, invalid message) */
} session_result;

/* run_symmetric_session - run the shared two-way session to completion; returns SESSION_USER_QUIT or SESSION_DISCONNECTED. See COMMENT_ARCHIVE.md. */
session_result run_symmetric_session(WOLFSSL *ssl, socket_t sock, int hw_fd,
                                      int oled_fd, const char *peer_label);

/* session_perform_local_destroy - performs "/destroy CONFIRM"'s local wipe effect. See COMMENT_ARCHIVE.md. */
void session_perform_local_destroy(void);

/* OUTBOX_DESTROY_SENTINEL - sentinel value enqueued in the offline outbox for a pending /destroy. See COMMENT_ARCHIVE.md. */
#define OUTBOX_DESTROY_SENTINEL "\x01SL_DESTROY_PENDING\x01"

/* IMPORTANT: run_symmetric_session() clears SO_RCVTIMEO on `sock` (to infinite) as its first action; must not be reintroduced. See COMMENT_ARCHIVE.md. */

#endif /* SESSION_H */

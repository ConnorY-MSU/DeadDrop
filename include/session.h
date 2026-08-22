#ifndef SESSION_H
#define SESSION_H

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Same portability shim as client.c/server.c, self-contained here rather
 * than relying on the including file to have already defined socket_t in
 * the right order - matches hw_expansion.h/hw_oled.h's self-contained
 * pattern. On 64-bit Windows, SOCKET is a 64-bit handle (UINT_PTR), NOT a
 * plain int - a plain `int sock` parameter here would silently truncate
 * it, a real bug worth avoiding by defining the actual portable type
 * rather than guessing at something "close enough". */
#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET socket_t;
#else
    typedef int socket_t;
#endif

/*
 * session - shared two-way interactive session, used by BOTH client.c and
 * server.c once their respective mTLS handshake completes.
 *
 * Deliberately factored into a real shared module, breaking from this
 * project's earlier "duplicate small glue functions between client.c and
 * server.c rather than share them" convention (see client.c's own comment
 * on that). That convention made sense for small, simple functions where
 * duplication cost little and avoided coupling; this is ~200 lines of
 * genuinely intricate, thread-safety-critical logic (a receiver thread
 * that must never be blocked by the sender, a mutex-protected shared
 * sl_session_state, a socket-shutdown trick to unblock a thread stuck in
 * a blocking read) - duplicating something this delicate across two files
 * would double the surface area for a subtle threading bug to hide in,
 * for no real benefit, since client.c and server.c now need functionally
 * identical two-way session behavior.
 *
 * Design, in brief (full reasoning in session.c):
 * - A receiver thread runs for the whole session, always processing and
 *   displaying incoming messages regardless of whether a human is
 *   actively typing right now - "receiving always works, replying is
 *   optional" was a deliberate choice to preserve this project's
 *   zero-manual-steps unattended-operation goal even for the server side.
 * - The calling thread reads stdin (with a bounded poll timeout, not a
 *   pure blocking read - see session.c) to optionally send messages.
 * - wolfSSL_write_dup() (needs HAVE_WRITE_DUP / --enable-writedup - see
 *   docs/BUILD.md) creates a genuinely separate write-only WOLFSSL* for
 *   the sender to use, so a blocking read on the original object never
 *   stalls the ability to write, and vice versa - wolfSSL's own docs are
 *   explicit that concurrent read+write on the SAME object from two
 *   threads is unsafe (a shared internal I/O buffer), so this isn't
 *   optional plumbing, it's the actual safety mechanism.
 * - sl_try_parse_message() is called exclusively from the receiver thread
 *   (only it ever reads incoming bytes), so the fields it touches
 *   (last_seen_seq_num/have_seen_any) need no cross-thread protection at
 *   all. sl_serialize_message()+wolfSSL_write(), however, can be called
 *   from EITHER thread - the local user's typed messages from the caller
 *   thread, and an automatic PONG reply to an incoming PING from the
 *   receiver thread - and both go out through the same single write-dup
 *   object. A send_mutex therefore wraps each *entire* send (serialize
 *   AND the wolfSSL_write() call together, not just the serialize step)
 *   as one atomic unit: splitting those into two separate critical
 *   sections would let one thread's write reach the wire ahead of
 *   another thread's earlier-assigned (lower) seq_num, or worse, let two
 *   wolfSSL_write() calls on the same object genuinely interleave mid-
 *   record - exactly the kind of concurrent-access corruption
 *   wolfSSL_write_dup() exists to avoid in the first place. This mutex
 *   only ever guards sends; it's never held around the receiver's
 *   blocking wolfSSL_read(), so an idle peer never stalls the ability to
 *   type and send a message.
 */

typedef enum {
    SESSION_USER_QUIT,    /* the local user explicitly quit (or stdin EOF) */
    SESSION_DISCONNECTED  /* the connection ended any other way - peer
                            * disconnected, a read/write failed, an
                            * invalid message arrived */
} session_result;

/*
 * run_symmetric_session - run the shared two-way session to completion.
 *
 * ssl: a WOLFSSL* whose handshake has already completed. This function
 *      calls wolfSSL_write_dup() on it internally and is responsible for
 *      freeing that duplicate before returning - the caller remains
 *      responsible for freeing `ssl` itself (unchanged from before).
 * sock: the raw socket underlying `ssl`, needed to forcibly and safely
 *      unblock the receiver thread's blocking read via shutdown() when
 *      the local side decides to end the session - see session.c for why
 *      this is necessary and why it's safe.
 * hw_fd: RGB status light fd (see hw_expansion.h) - may be -1.
 * oled_fd: OLED fd (see hw_oled.h) - may be -1.
 * peer_label: short text describing who's on the other end (e.g.
 *      "server" or "client"), used only for console/OLED labeling of
 *      incoming messages - never sent over the wire, no protocol role.
 *
 * Returns SESSION_USER_QUIT or SESSION_DISCONNECTED - see the enum above.
 */
session_result run_symmetric_session(WOLFSSL *ssl, socket_t sock, int hw_fd,
                                      int oled_fd, const char *peer_label);

#endif /* SESSION_H */

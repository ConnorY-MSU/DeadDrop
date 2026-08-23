#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* --- Wire format constants, matching docs/PROTOCOL.md exactly --- */

#define SL_VERSION          1

#define SL_HEADER_SIZE      12   /* version(1) + msg_type(1) + reserved(2)
                                   * + seq_num(4) + body_length(4) */
#define SL_HMAC_SIZE         32
#define SL_MAX_BODY_LEN   65536  /* PROTOCOL.md: 64 KiB cap */
#define SL_MAX_MSG_SIZE     (SL_HEADER_SIZE + SL_MAX_BODY_LEN + SL_HMAC_SIZE)

#define SL_HMAC_KEY_SIZE     32

/* TLS exporter label used to derive the per-session HMAC key. Prefixed
 * EXPERIMENTAL- per RFC 8446 4.2.7 since it's not an IANA-registered
 * label. See docs/PROTOCOL.md "HMAC key derivation". */
#define SL_HMAC_KEY_LABEL "EXPERIMENTAL-SecureLink-HMAC-Key"

typedef enum {
    SL_MSG_TEXT_MESSAGE = 0x01,
    SL_MSG_PING         = 0x02,
    SL_MSG_PONG         = 0x03,
    SL_MSG_DISCONNECT   = 0x04,
    SL_MSG_ACK          = 0x05, /* body: 4 bytes BE, the seq_num of the
                                    TEXT_MESSAGE being acknowledged - see
                                    docs/PROTOCOL.md */
    SL_MSG_FILE         = 0x06, /* body: [2-byte filename_len BE]
                                    [filename bytes][file data] - see
                                    docs/PROTOCOL.md for the size cap */
    SL_MSG_DESTROY      = 0x07  /* body: none. The "/destroy CONFIRM"
                                    emergency-wipe command - see
                                    docs/PROTOCOL.md and session.c's
                                    perform_local_destroy(). No body/nonce
                                    needed: this arrives over an already
                                    mutually-authenticated, replay-protected
                                    session (see seq_num handling below),
                                    so its mere authenticated arrival is
                                    the only confirmation that matters -
                                    the peer's own identity already proved
                                    itself during the mTLS handshake. */
} sl_msg_type;

#define SL_FILE_NAME_LEN_SIZE 2 /* the 2-byte length prefix within a
    SL_MSG_FILE body - kept as its own constant since both the sender
    (building the body) and receiver (parsing it back apart) need to
    agree on this exact offset */
#define SL_FILE_NAME_MAX 255   /* generous for a real filename, small
    enough that even a maximally-long name still leaves the overwhelming
    majority of SL_MAX_BODY_LEN for actual file content */

/*
 * Per-TLS-session framing/replay state. Create one fresh instance per
 * connection (client: per connect; server: per accepted connection) via
 * sl_session_init() -- this is what makes seq_num reset to 0 on every new
 * session, as docs/PROTOCOL.md requires: the state simply doesn't exist
 * yet for a session until sl_session_init() creates it.
 */
typedef struct {
    uint8_t  hmac_key[SL_HMAC_KEY_SIZE]; /* derived via TLS exporter */
    uint32_t next_seq_num;               /* next seq_num WE will send */
    uint32_t last_seen_seq_num;          /* last seq_num accepted FROM peer */
    int      have_seen_any;              /* 0 until first peer msg accepted */
} sl_session_state;

/*
 * sl_session_init - derive the per-session HMAC key from the already-
 * completed TLS 1.3 handshake (via wolfSSL_export_keying_material(), RFC
 * 5705/RFC 8446 7.5) and reset seq_num state for a brand new session.
 *
 * ssl: a WOLFSSL* whose handshake (wolfSSL_connect/wolfSSL_accept) has
 *      already completed successfully.
 * state: caller-owned state to initialize.
 * Returns 0 on success, -1 if the exporter call fails (e.g. this
 * wolfSSL build lacks HAVE_KEYING_MATERIAL -- see docs/BUILD.md).
 */
int sl_session_init(WOLFSSL *ssl, sl_session_state *state);

/*
 * sl_serialize_message - build one complete wire message (header + body +
 * HMAC tag) into out_buf, and consume the next outgoing seq_num.
 *
 * state: session state; state->next_seq_num is used and then incremented.
 * msg_type: one of the sl_msg_type values.
 * body/body_len: message payload. body may be NULL iff body_len == 0.
 * out_buf/out_buf_size: caller-owned destination buffer.
 *
 * Returns the total number of bytes written (>0) on success, or -1 if
 * body_len exceeds SL_MAX_BODY_LEN or out_buf_size is too small.
 */
int sl_serialize_message(sl_session_state *state, uint8_t msg_type,
                          const uint8_t *body, uint32_t body_len,
                          uint8_t *out_buf, size_t out_buf_size);

typedef enum {
    SL_PARSE_INCOMPLETE = 0, /* not enough bytes buffered yet - read more */
    SL_PARSE_OK         = 1, /* one full, valid message parsed */
    SL_PARSE_REJECTED   = 2  /* a full message was present but failed
                               * validation (bad version/type/seq/hmac) */
} sl_parse_result;

typedef struct {
    uint8_t        version;
    uint8_t        msg_type;
    uint32_t       seq_num;
    uint32_t       body_len;
    const uint8_t *body; /* points into caller's buffer; not owned/copied */
} sl_parsed_message;

/*
 * sl_try_parse_message - attempt to parse exactly one message from the
 * front of buf[0..have). Designed to be called in a loop: after consuming
 * one message, call again on the remainder to pick up a second message
 * that arrived in the same read() (see docs -- this is the "single
 * wolfSSL_read() returning two messages at once" case).
 *
 * state: session state; on SL_PARSE_OK, last_seen_seq_num/have_seen_any
 *        are updated. Not modified on SL_PARSE_INCOMPLETE or REJECTED.
 * buf/have: the receive buffer and how many valid bytes are in it.
 * out_msg: filled in on SL_PARSE_OK (body points into buf - copy it out
 *          before the caller memmove()s the buffer if you need to keep it).
 * consumed: on SL_PARSE_OK or SL_PARSE_REJECTED with a full message
 *           present, set to the number of bytes that message occupied --
 *           caller must memmove/advance past exactly this many bytes.
 *           On SL_PARSE_INCOMPLETE, or on the "implausible body_length"
 *           rejection case, *consumed is set to 0: the receiver cannot
 *           determine a message boundary at all in that situation, and
 *           the connection should be treated as desynchronized and closed
 *           rather than resynchronized speculatively.
 *
 * Returns SL_PARSE_INCOMPLETE if buf doesn't yet hold a full message.
 */
sl_parse_result sl_try_parse_message(sl_session_state *state,
                                      const uint8_t *buf, size_t have,
                                      sl_parsed_message *out_msg,
                                      size_t *consumed);

#endif // MESSAGE_H
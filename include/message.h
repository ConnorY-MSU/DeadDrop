#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* --- Wire format constants, matching docs/PROTOCOL.md exactly --- */

#define DD_VERSION          1

#define DD_HEADER_SIZE      12   /* version(1) + msg_type(1) + reserved(2) + seq_num(4) + body_length(4) */
#define DD_HMAC_SIZE         32
#define DD_MAX_BODY_LEN   65536  /* PROTOCOL.md: 64 KiB cap */
#define DD_MAX_MSG_SIZE     (DD_HEADER_SIZE + DD_MAX_BODY_LEN + DD_HMAC_SIZE)

#define DD_HMAC_KEY_SIZE     32

/* TLS exporter label used to derive the per-session HMAC key; EXPERIMENTAL- prefix per RFC 8446 4.2.7 (not IANA-registered). */
#define DD_HMAC_KEY_LABEL "EXPERIMENTAL-DeadDrop-HMAC-Key"

typedef enum {
    DD_MSG_TEXT_MESSAGE = 0x01,
    DD_MSG_PING         = 0x02,
    DD_MSG_PONG         = 0x03,
    DD_MSG_DISCONNECT   = 0x04,
    DD_MSG_ACK          = 0x05, /* body: 4 bytes BE, the seq_num of the TEXT_MESSAGE being acknowledged */
    DD_MSG_FILE         = 0x06, /* body: [2-byte filename_len BE][filename bytes][file data] */
    DD_MSG_DESTROY      = 0x07  /* body: none; the "/destroy CONFIRM" emergency-wipe command, no nonce needed (already authenticated/replay-protected) */
} dd_msg_type;

#define DD_FILE_NAME_LEN_SIZE 2 /* 2-byte length prefix within a DD_MSG_FILE body */
#define DD_FILE_NAME_MAX 255   /* generous for a real filename, leaves most of DD_MAX_BODY_LEN for actual file content */

/* Per-TLS-session framing/replay state; create one fresh instance per connection via dd_session_init(). */
typedef struct {
    uint8_t  hmac_key[DD_HMAC_KEY_SIZE]; /* derived via TLS exporter */
    uint32_t next_seq_num;               /* next seq_num WE will send */
    uint32_t last_seen_seq_num;          /* last seq_num accepted FROM peer */
    int      have_seen_any;              /* 0 until first peer msg accepted */
} dd_session_state;

/* dd_session_init - derive the per-session HMAC key from the completed TLS 1.3 handshake and reset seq_num state. Returns 0, or -1 on failure. */
int dd_session_init(WOLFSSL *ssl, dd_session_state *state);

/* dd_serialize_message - build one complete wire message (header + body + HMAC tag) into out_buf, consuming the next seq_num. Returns bytes written, or -1. */
int dd_serialize_message(dd_session_state *state, uint8_t msg_type,
                          const uint8_t *body, uint32_t body_len,
                          uint8_t *out_buf, size_t out_buf_size);

typedef enum {
    DD_PARSE_INCOMPLETE = 0, /* not enough bytes buffered yet - read more */
    DD_PARSE_OK         = 1, /* one full, valid message parsed */
    DD_PARSE_REJECTED   = 2  /* a full message was present but failed validation (bad version/type/seq/hmac) */
} dd_parse_result;

typedef struct {
    uint8_t        version;
    uint8_t        msg_type;
    uint32_t       seq_num;
    uint32_t       body_len;
    const uint8_t *body; /* points into caller's buffer; not owned/copied */
} dd_parsed_message;

/* dd_try_parse_message - parse one message from buf[0..have); call in a loop for multiple messages. out_msg->body points into buf - copy before memmove(). */
dd_parse_result dd_try_parse_message(dd_session_state *state,
                                      const uint8_t *buf, size_t have,
                                      dd_parsed_message *out_msg,
                                      size_t *consumed);

#endif // MESSAGE_H
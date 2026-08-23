#include "message.h"
#include "hmac.h"
#include <string.h>
#include <stdio.h>

static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Constant-time-ish comparison for the HMAC tag: always walks the full
 * length rather than short-circuiting on the first mismatched byte, so
 * how quickly this returns doesn't leak how many leading bytes matched. */
static int consttime_tag_cmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (a[i] ^ b[i]));
    }
    return diff; /* 0 iff equal */
}

int sl_session_init(WOLFSSL *ssl, sl_session_state *state)
{
    int rc;

    memset(state, 0, sizeof(*state));

    rc = wolfSSL_export_keying_material(
        ssl,
        state->hmac_key, sizeof(state->hmac_key),
        SL_HMAC_KEY_LABEL, strlen(SL_HMAC_KEY_LABEL),
        NULL, 0,   /* no context value (use_context = 0 below) */
        0);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char errbuf[80];
        fprintf(stderr,
            "sl_session_init: wolfSSL_export_keying_material failed "
            "(rc=%d, err=%d: %s) - did the caller call "
            "wolfSSL_KeepArrays(ssl) before the handshake? wolfSSL frees "
            "handshake arrays after completion by default, and the "
            "exporter needs them.\n",
            rc, err, wolfSSL_ERR_error_string(err, errbuf));
        return -1;
    }

    /* The handshake arrays kept alive via the caller's pre-handshake
     * wolfSSL_KeepArrays(ssl) call are only needed for this one export
     * call - free them now rather than holding that memory for the rest
     * of a potentially long-lived interactive session. */
    wolfSSL_FreeArrays(ssl);

    state->next_seq_num      = 0;
    state->last_seen_seq_num = 0;
    state->have_seen_any     = 0;

    return 0;
}

int sl_serialize_message(sl_session_state *state, uint8_t msg_type,
                          const uint8_t *body, uint32_t body_len,
                          uint8_t *out_buf, size_t out_buf_size)
{
    size_t total;

    if (body_len > SL_MAX_BODY_LEN) {
        return -1;
    }
    if (body_len > 0 && body == NULL) {
        return -1;
    }

    total = (size_t)SL_HEADER_SIZE + body_len + SL_HMAC_SIZE;
    if (out_buf_size < total) {
        return -1;
    }

    out_buf[0] = SL_VERSION;
    out_buf[1] = msg_type;
    out_buf[2] = 0;
    out_buf[3] = 0; /* reserved, must be sent as 0x0000 */
    put_u32_be(out_buf + 4, state->next_seq_num);
    put_u32_be(out_buf + 8, body_len);

    if (body_len > 0) {
        memcpy(out_buf + SL_HEADER_SIZE, body, body_len);
    }

    /* HMAC covers header + body -- everything before the tag itself. */
    hmac_sha256(state->hmac_key, sizeof(state->hmac_key),
                out_buf, SL_HEADER_SIZE + body_len,
                out_buf + SL_HEADER_SIZE + body_len);

    state->next_seq_num++;

    return (int)total;
}

sl_parse_result sl_try_parse_message(sl_session_state *state,
                                      const uint8_t *buf, size_t have,
                                      sl_parsed_message *out_msg,
                                      size_t *consumed)
{
    uint32_t body_len;
    size_t total;
    uint8_t computed_tag[SL_HMAC_SIZE];

    /* Can't even read body_length yet. */
    if (have < SL_HEADER_SIZE) {
        return SL_PARSE_INCOMPLETE;
    }

    body_len = get_u32_be(buf + 8);

    /* A claimed body_length beyond the protocol's own maximum can never
     * be legitimate. Waiting for that many bytes to arrive would just
     * hang the connection (or, worse, be an attacker trying to get us to
     * allocate/wait indefinitely) -- reject immediately. Because we
     * cannot trust body_length here, we also cannot know where this
     * "message" actually ends, so *consumed is left at 0: there is no
     * safe resync point, and the caller should close the connection
     * rather than keep parsing this buffer. */
    if (body_len > SL_MAX_BODY_LEN) {
        *consumed = 0;
        return SL_PARSE_REJECTED;
    }

    total = (size_t)SL_HEADER_SIZE + body_len + SL_HMAC_SIZE;
    if (have < total) {
        return SL_PARSE_INCOMPLETE;
    }

    /* From here on we know the full message is buffered, so *consumed is
     * always set to `total` before returning, on both OK and REJECTED --
     * a rejected-but-well-framed message still occupied exactly `total`
     * bytes of the stream and must be skipped as a whole. */
    *consumed = total;

    out_msg->version  = buf[0];
    out_msg->msg_type = buf[1];
    out_msg->seq_num  = get_u32_be(buf + 4);
    out_msg->body_len = body_len;
    out_msg->body     = buf + SL_HEADER_SIZE;

    if (out_msg->version != SL_VERSION) {
        return SL_PARSE_REJECTED;
    }

    switch (out_msg->msg_type) {
        case SL_MSG_TEXT_MESSAGE:
        case SL_MSG_PING:
        case SL_MSG_PONG:
        case SL_MSG_DISCONNECT:
        case SL_MSG_ACK:
        case SL_MSG_FILE:
        case SL_MSG_DESTROY:
            break;
        default:
            return SL_PARSE_REJECTED;
    }

    /* Replay/reorder check: strictly greater than the last seq_num we've
     * accepted from this peer in this session. */
    if (state->have_seen_any && out_msg->seq_num <= state->last_seen_seq_num) {
        return SL_PARSE_REJECTED;
    }

    hmac_sha256(state->hmac_key, sizeof(state->hmac_key),
                buf, SL_HEADER_SIZE + body_len, computed_tag);
    if (consttime_tag_cmp(computed_tag, buf + SL_HEADER_SIZE + body_len,
                           SL_HMAC_SIZE) != 0) {
        return SL_PARSE_REJECTED;
    }

    /* Only advance replay state once a message is fully accepted --
     * a rejected message (e.g. failed HMAC) must not move this forward,
     * or a single spoofed high seq_num could be used to lock out every
     * legitimate message that follows it. */
    state->last_seen_seq_num = out_msg->seq_num;
    state->have_seen_any = 1;

    return SL_PARSE_OK;
}
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "message.h"
#include "hmac.h"

/* Unit tests for dd_serialize_message()/dd_try_parse_message(), isolated from wolfSSL/TLS via a fixed test key; checks wire-format/HMAC/seq_num logic against docs/PROTOCOL.md. */

static int all_pass = 1;

static void check(const char *name, int actual, int expected) {
    int ok = (actual == expected);
    printf("[%s] %s (got %d, expected %d)\n", ok ? "PASS" : "FAIL", name, actual, expected);
    if (!ok) all_pass = 0;
}

static void check_bytes(const char *name, const uint8_t *actual, const uint8_t *expected, size_t len) {
    int ok = (memcmp(actual, expected, len) == 0);
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) all_pass = 0;
}

/* Fixed test key standing in for a real TLS-derived key; shared by sender and receiver like a real session. */
static const uint8_t test_key[DD_HMAC_KEY_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static void init_state(dd_session_state *s) {
    memset(s, 0, sizeof(*s));
    memcpy(s->hmac_key, test_key, sizeof(test_key));
}

/* Recomputes the HMAC tag over buf[0 .. total-33) so a test isolates a corrupted field's rejection from a stale-HMAC failure. */
static void refresh_tag(uint8_t *buf, size_t total) {
    hmac_sha256(test_key, sizeof(test_key), buf, total - DD_HMAC_SIZE, buf + total - DD_HMAC_SIZE);
}

int main(void) {
    uint8_t buf[DD_MAX_MSG_SIZE];
    dd_session_state sender, receiver;
    dd_parsed_message msg;
    size_t consumed;
    dd_parse_result pr;
    int total;

    /* --- Test 1: basic round-trip --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    check("serialize returns correct total size (12+5+32)", total, 12 + 5 + 32);

    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("round-trip: parse result is OK", pr, DD_PARSE_OK);
    check("round-trip: consumed == total", (int)consumed, total);
    check("round-trip: version", msg.version, DD_VERSION);
    check("round-trip: msg_type", msg.msg_type, DD_MSG_TEXT_MESSAGE);
    check("round-trip: seq_num", (int)msg.seq_num, 0);
    check("round-trip: body_len", (int)msg.body_len, 5);
    check_bytes("round-trip: body content", msg.body, (const uint8_t *)"hello", 5);

    /* Hand-verify the byte layout against docs/PROTOCOL.md's worked example (msg_type=1, seq_num=0, body="hello"). */
    {
        static const uint8_t expected_prefix[17] = {
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F
        };
        check_bytes("wire bytes match PROTOCOL.md's worked example exactly",
                    buf, expected_prefix, sizeof(expected_prefix));
    }

    /* --- Test 2: HMAC tag tamper is detected --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    buf[total - 1] ^= 0xFF; /* flip the last tag byte */
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("tampered HMAC tag is rejected", pr, DD_PARSE_REJECTED);

    /* --- Test 3: body tamper is detected (HMAC covers the body too) --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    buf[12] ^= 0xFF; /* flip the first body byte, leave the (now-stale) tag alone */
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("tampered body is rejected", pr, DD_PARSE_REJECTED);

    /* --- Test 4/5: seq_num replay and reordering --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"first", 5, buf, sizeof(buf));
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("first message (seq=0) accepted", pr, DD_PARSE_OK);

    /* Exact replay of the same bytes (same seq_num=0) must now be rejected. */
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("exact replay of seq=0 is rejected after seq=0 already accepted", pr, DD_PARSE_REJECTED);

    /* The next real message (seq=1) must be accepted. */
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"second", 6, buf, sizeof(buf));
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("next message (seq=1) is accepted", pr, DD_PARSE_OK);
    check("seq_num correctly advanced to 1", (int)msg.seq_num, 1);

    /* --- Test 6: implausible body_length is rejected before being trusted --- */
    {
        uint8_t bad_header[DD_HEADER_SIZE];
        memset(bad_header, 0, sizeof(bad_header));
        bad_header[0] = DD_VERSION;
        bad_header[1] = DD_MSG_TEXT_MESSAGE;
        /* body_length = DD_MAX_BODY_LEN + 1, big-endian, at offset 8 */
        {
            uint32_t bad_len = DD_MAX_BODY_LEN + 1;
            bad_header[8] = (uint8_t)(bad_len >> 24);
            bad_header[9] = (uint8_t)(bad_len >> 16);
            bad_header[10] = (uint8_t)(bad_len >> 8);
            bad_header[11] = (uint8_t)(bad_len);
        }
        consumed = 999; /* poison, to confirm it actually gets set to 0 */
        pr = dd_try_parse_message(&receiver, bad_header, sizeof(bad_header), &msg, &consumed);
        check("body_length > DD_MAX_BODY_LEN is rejected", pr, DD_PARSE_REJECTED);
        check("no safe resync point: consumed set to 0", (int)consumed, 0);
    }

    /* --- Test 7: partial/incomplete messages --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, 5, &msg, &consumed);
    check("fewer bytes than the header (5) is INCOMPLETE, not REJECTED", pr, DD_PARSE_INCOMPLETE);
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)(total - 1), &msg, &consumed);
    check("one byte short of a complete message is INCOMPLETE", pr, DD_PARSE_INCOMPLETE);
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("the full message now parses OK", pr, DD_PARSE_OK);

    /* --- Test 8: unrecognized version is rejected --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    buf[0] = 2; /* DD_VERSION is 1 - this is unrecognized */
    refresh_tag(buf, (size_t)total); /* isolate: HMAC is valid, ONLY the version is wrong */
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("unrecognized version is rejected (HMAC otherwise valid)", pr, DD_PARSE_REJECTED);

    /* --- Test 9: unrecognized msg_type is rejected --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_TEXT_MESSAGE,
                                  (const uint8_t *)"hello", 5, buf, sizeof(buf));
    buf[1] = 0x99; /* not one of TEXT_MESSAGE/PING/PONG/DISCONNECT */
    refresh_tag(buf, (size_t)total); /* isolate: HMAC is valid, ONLY the type is wrong */
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("unrecognized msg_type is rejected (HMAC otherwise valid)", pr, DD_PARSE_REJECTED);

    /* --- Test 10: two messages arriving in a single buffer parse independently --- */
    {
        uint8_t combined[DD_MAX_MSG_SIZE * 2];
        int total_a, total_b;
        size_t consumed_a, consumed_b;

        init_state(&sender);
        init_state(&receiver);
        total_a = dd_serialize_message(&sender, DD_MSG_PING, NULL, 0, combined, sizeof(combined));
        total_b = dd_serialize_message(&sender, DD_MSG_PONG, NULL, 0,
                                        combined + total_a, sizeof(combined) - (size_t)total_a);

        pr = dd_try_parse_message(&receiver, combined, (size_t)(total_a + total_b), &msg, &consumed_a);
        check("first of two buffered messages: parse OK", pr, DD_PARSE_OK);
        check("first message type is PING", msg.msg_type, DD_MSG_PING);
        check("first message consumed == its own size only", (int)consumed_a, total_a);

        pr = dd_try_parse_message(&receiver, combined + consumed_a,
                                   (size_t)(total_a + total_b) - consumed_a, &msg, &consumed_b);
        check("second of two buffered messages: parse OK", pr, DD_PARSE_OK);
        check("second message type is PONG", msg.msg_type, DD_MSG_PONG);
        check("second message seq_num advanced to 1", (int)msg.seq_num, 1);
    }

    /* --- Test 11: DISCONNECT (zero-length body) round-trips correctly --- */
    init_state(&sender);
    init_state(&receiver);
    total = dd_serialize_message(&sender, DD_MSG_DISCONNECT, NULL, 0, buf, sizeof(buf));
    check("DISCONNECT total size is exactly header+tag, no body", total, DD_HEADER_SIZE + DD_HMAC_SIZE);
    consumed = 0;
    pr = dd_try_parse_message(&receiver, buf, (size_t)total, &msg, &consumed);
    check("DISCONNECT round-trips OK", pr, DD_PARSE_OK);
    check("DISCONNECT body_len is 0", (int)msg.body_len, 0);

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}

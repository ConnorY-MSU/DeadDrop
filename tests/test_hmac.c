#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hmac.h"
#include "debug.h"

/* Test vectors from RFC 4231 ("Identifiers and Test Vectors for HMAC-SHA-224,
 * HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512"), the standard reference
 * vectors for HMAC-SHA-256 - same "known-good external standard, not just
 * internal self-consistency" discipline as Week 1's SHA-256/AES-128 vectors. */

static size_t hex_to_bytes(const char *hex_str, uint8_t *out) {
    size_t len = strlen(hex_str) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex_str + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
    return len;
}

static int check_digest(const char *test_name, const uint8_t *actual, const char *expected_hex) {
    uint8_t expected[32];
    hex_to_bytes(expected_hex, expected);
    int match = memcmp(actual, expected, 32) == 0;
    printf("[%s] %s\n", match ? "PASS" : "FAIL", test_name);
    if (!match) {
        print_hex("  got     ", actual, 32);
        print_hex("  expected", expected, 32);
    }
    return match;
}

static int run_vector(const char *name, const char *key_hex, const char *data,
                       size_t data_len, const char *expected_hex) {
    uint8_t key[256];
    size_t key_len = hex_to_bytes(key_hex, key);
    uint8_t digest[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(key, key_len, (const uint8_t *)data, data_len, digest);
    return check_digest(name, digest, expected_hex);
}

int main(void) {
    int all_pass = 1;

    /* RFC 4231 Test Case 1: 20-byte key, "Hi There" */
    all_pass &= run_vector(
        "RFC 4231 Test Case 1 (20-byte key)",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    /* RFC 4231 Test Case 2: "Jefe" / "what do ya want for nothing?" -
     * the most commonly cited HMAC-SHA-256 vector, key shorter than a block. */
    all_pass &= run_vector(
        "RFC 4231 Test Case 2 (short key, \"Jefe\")",
        "4a656665",
        "what do ya want for nothing?", 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );

    /* RFC 4231 Test Case 3: 20-byte 0xaa key, 50-byte 0xdd data. */
    {
        char data[50];
        memset(data, 0xdd, sizeof(data));
        all_pass &= run_vector(
            "RFC 4231 Test Case 3 (0xdd-filled data)",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            data, sizeof(data),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /* RFC 4231 Test Case 6: key LONGER than SHA-256's 64-byte block size
     * (131 bytes) - specifically exercises the "hash the key down to 32
     * bytes first" branch in hmac_sha256()'s own key-padding logic (RFC
     * 2104 step 1/5.a), which none of the vectors above touch at all. */
    {
        char key_hex[263];
        char data[] = "Test Using Larger Than Block-Size Key - Hash Key First";
        size_t i;
        for (i = 0; i < 131; i++) {
            key_hex[i * 2] = 'a';
            key_hex[i * 2 + 1] = 'a';
        }
        key_hex[262] = '\0';
        all_pass &= run_vector(
            "RFC 4231 Test Case 6 (key > block size)",
            key_hex,
            data, sizeof(data) - 1,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}

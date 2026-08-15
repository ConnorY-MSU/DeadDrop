#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "aes128.h"
#include "debug.h"

static size_t hex_to_bytes(const char *hex_str, uint8_t *out) {
    size_t len = strlen(hex_str) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex_str + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
    return len;
}

static int check_block(const char *test_name, const uint8_t *actual, const char *expected_hex) {
    uint8_t expected[16];
    hex_to_bytes(expected_hex, expected);
    int match = memcmp(actual, expected, 16) == 0;
    printf("[%s] %s\n", match ? "PASS" : "FAIL", test_name);
    if (!match) {
        print_hex("  got     ", actual, 16);
        print_hex("  expected", expected, 16);
    }
    return match;
}

int main(void) {
    int all_pass = 1;

    /* FIPS 197 Appendix B official test vector */
    uint8_t key[16];
    uint8_t plaintext[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", key);
    hex_to_bytes("00112233445566778899aabbccddeeff", plaintext);

    uint8_t round_key[AES128_ROUND_KEY_SIZE];
    aes128_key_expansion(key, round_key);

    uint8_t ciphertext[16];
    aes128_encrypt_block(round_key, plaintext, ciphertext);

    all_pass &= check_block(
        "FIPS-197 Appendix B single-block encrypt",
        ciphertext,
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    );

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}

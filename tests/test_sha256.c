#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "sha256.h"
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

static int run_vector(const char *name, const char *msg, size_t msg_len, const char *expected_hex) {
    sha256_context ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, msg_len);
    sha256_final(&ctx, digest);
    return check_digest(name, digest, expected_hex);
}

int main(void) {
    int all_pass = 1;

    all_pass &= run_vector(
        "empty string",
        "", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    all_pass &= run_vector(
        "\"abc\" (single block)",
        "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    all_pass &= run_vector(
        "56-byte message (forces two blocks)",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}

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

    uint8_t known_ciphertext[16];
    hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a", known_ciphertext);

    uint8_t decrypted[16];
    aes128_decrypt_block(round_key, known_ciphertext, decrypted);

    all_pass &= check_block(
        "FIPS-197 Appendix B single-block decrypt",
        decrypted,
        "00112233445566778899aabbccddeeff"
    );

    uint8_t roundtrip_plain[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", roundtrip_plain);

    uint8_t roundtrip_cipher[16];
    aes128_encrypt_block(round_key, roundtrip_plain, roundtrip_cipher);

    uint8_t roundtrip_decrypted[16];
    aes128_decrypt_block(round_key, roundtrip_cipher, roundtrip_decrypted);

    int roundtrip_ok = memcmp(roundtrip_plain, roundtrip_decrypted, 16) == 0;
    printf("[%s] Round-trip: encrypt then decrypt returns original plaintext\n", roundtrip_ok ? "PASS" : "FAIL");
    if (!roundtrip_ok) {
        print_hex("  original ", roundtrip_plain, 16);
        print_hex("  decrypted", roundtrip_decrypted, 16);
    }
    all_pass &= roundtrip_ok;

    uint8_t key2[16];
    uint8_t plaintext2[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key2);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", plaintext2);

    uint8_t round_key2[AES128_ROUND_KEY_SIZE];
    aes128_key_expansion(key2, round_key2);

    uint8_t ciphertext2[16];
    aes128_encrypt_block(round_key2, plaintext2, ciphertext2);

    all_pass &= check_block(
        "NIST SP800-38A F.1.1 block #1 encrypt",
        ciphertext2,
        "3ad77bb40d7a3660a89ecaf32466ef97"
    );

    uint8_t known_ciphertext2[16];
    hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97", known_ciphertext2);

    uint8_t decrypted2[16];
    aes128_decrypt_block(round_key2, known_ciphertext2, decrypted2);

    all_pass &= check_block(
        "NIST SP800-38A F.1.1 block #1 decrypt",
        decrypted2,
        "6bc1bee22e409f96e93d7e117393172a"
    );

    /* NIST SP 800-38A F.5.1 CTR-AES128, all 4 blocks, one call */
    uint8_t ctr_key[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", ctr_key);
    uint8_t ctr_round_key[AES128_ROUND_KEY_SIZE];
    aes128_key_expansion(ctr_key, ctr_round_key);

    uint8_t initial_counter[16];
    hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", initial_counter);

    uint8_t ctr_plaintext[64];
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", ctr_plaintext);
    hex_to_bytes("ae2d8a571e03ac9c9eb76fac45af8e51", ctr_plaintext + 16);
    hex_to_bytes("30c81c46a35ce411e5fbc1191a0a52ef", ctr_plaintext + 32);
    hex_to_bytes("f69f2445df4f9b17ad2b417be66c3710", ctr_plaintext + 48);

    uint8_t ctr_ciphertext[64];
    aes128_ctr_xcrypt(ctr_round_key, initial_counter, ctr_plaintext, ctr_ciphertext, 64);

    all_pass &= check_block("SP800-38A F.5.1 CTR block 1", ctr_ciphertext,      "874d6191b620e3261bef6864990db6ce");
    all_pass &= check_block("SP800-38A F.5.1 CTR block 2", ctr_ciphertext + 16, "9806f66b7970fdff8617187bb9fffdff");
    all_pass &= check_block("SP800-38A F.5.1 CTR block 3", ctr_ciphertext + 32, "5ae4df3edbd5d35e5b4f09020db03eab");
    all_pass &= check_block("SP800-38A F.5.1 CTR block 4", ctr_ciphertext + 48, "1e031dda2fbe03d1792170a0f3009cee");

    /* Decrypt: same function, feeding the ciphertext back through with a fresh copy of the same initial counter */
    uint8_t ctr_decrypted[64];
    aes128_ctr_xcrypt(ctr_round_key, initial_counter, ctr_ciphertext, ctr_decrypted, 64);

    int ctr_roundtrip_ok = memcmp(ctr_plaintext, ctr_decrypted, 64) == 0;
    printf("[%s] CTR round-trip: decrypt(encrypt(P)) == P\n", ctr_roundtrip_ok ? "PASS" : "FAIL");
    all_pass &= ctr_roundtrip_ok;

    /* Multi-block round-trip, per Day 4 checklist: an odd, non-block-aligned length */
    uint8_t odd_plain[37];
    for (size_t i = 0; i < sizeof(odd_plain); i++) odd_plain[i] = (uint8_t)i;
    uint8_t odd_cipher[37], odd_decrypted[37];
    uint8_t odd_counter[16];
    hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", odd_counter);
    aes128_ctr_xcrypt(ctr_round_key, odd_counter, odd_plain, odd_cipher, sizeof(odd_plain));
    hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", odd_counter);
    aes128_ctr_xcrypt(ctr_round_key, odd_counter, odd_cipher, odd_decrypted, sizeof(odd_plain));
    int odd_ok = memcmp(odd_plain, odd_decrypted, sizeof(odd_plain)) == 0;
    printf("[%s] CTR round-trip on non-block-aligned length (37 bytes)\n", odd_ok ? "PASS" : "FAIL");
    all_pass &= odd_ok;

    /* ECB demonstration: two identical plaintext blocks, raw block cipher, no mode.
       This is deliberately NOT how you'd ever actually use the cipher -- it's here
       to prove, not just assert, why raw ECB leaks structure. */
    uint8_t ecb_block_a[16], ecb_block_b[16];
    hex_to_bytes("11111111111111111111111111111111", ecb_block_a); /* identical plaintext on purpose */
    hex_to_bytes("11111111111111111111111111111111", ecb_block_b);

    uint8_t ecb_cipher_a[16], ecb_cipher_b[16];
    aes128_encrypt_block(round_key, ecb_block_a, ecb_cipher_a);
    aes128_encrypt_block(round_key, ecb_block_b, ecb_cipher_b);

    int ecb_leak = memcmp(ecb_cipher_a, ecb_cipher_b, 16) == 0;
    printf("[%s] ECB demonstration: identical plaintext blocks produce identical ciphertext blocks\n",
           ecb_leak ? "PASS" : "FAIL");
    if (ecb_leak) {
        print_hex("  plaintext block A ", ecb_block_a, 16);
        print_hex("  plaintext block B ", ecb_block_b, 16);
        print_hex("  ciphertext block A", ecb_cipher_a, 16);
        print_hex("  ciphertext block B", ecb_cipher_b, 16);
        printf("  -> identical plaintext blocks under the same key ALWAYS produce identical\n");
        printf("     ciphertext blocks in raw ECB -- this is the exact leak behind the \"ECB\n");
        printf("     penguin\" image. This is why DeadDrop never uses raw ECB as a mode.\n");
    }
    all_pass &= ecb_leak;

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}
#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

#define AES128_KEY_SIZE 16
#define AES128_ROUND_KEY_SIZE 176   // (10 rounds + 1) * 16 bytes

/* aes128_key_expansion - derive all 11 round keys (round n at round_key[n*16, n*16+16)) from key; call once per key before encrypt/decrypt/CTR. */
void aes128_key_expansion(const uint8_t key[AES128_KEY_SIZE],
                          uint8_t round_key[AES128_ROUND_KEY_SIZE]);

/* aes128_encrypt_block - raw AES-128 single-block encrypt (no mode); use aes128_ctr_xcrypt() for messages longer than one block. */
void aes128_encrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

/* aes128_decrypt_block - decrypt a single 16-byte block (inverse of aes128_encrypt_block); uses the same round_key, inverse order handled internally. */
void aes128_decrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

/* aes128_ctr_xcrypt - CTR-mode encrypt/decrypt (same op) of length bytes; nonce_counter is not modified; NEVER reuse a (key, counter) pair across messages. */
void aes128_ctr_xcrypt(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                        const uint8_t nonce_counter[16],
                        const uint8_t *input,
                        uint8_t *output,
                        size_t length);
#endif // AES128_H

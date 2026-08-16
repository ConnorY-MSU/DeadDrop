#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

#define AES128_KEY_SIZE 16
#define AES128_ROUND_KEY_SIZE 176   // (10 rounds + 1) * 16 bytes

void aes128_key_expansion(const uint8_t key[AES128_KEY_SIZE],
                          uint8_t round_key[AES128_ROUND_KEY_SIZE]);

void aes128_encrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

void aes128_decrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

void aes128_ctr_xcrypt(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                        const uint8_t nonce_counter[16],
                        const uint8_t *input,
                        uint8_t *output,
                        size_t length);
#endif // AES128_H

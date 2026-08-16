#ifndef AES128_H
#define AES128_H

#include <stdint.h>
#include <stddef.h>

#define AES128_KEY_SIZE 16
#define AES128_ROUND_KEY_SIZE 176   // (10 rounds + 1) * 16 bytes

/*
 * aes128_key_expansion - derive all 11 round keys from a 128-bit key.
 * key:       16-byte AES-128 key.
 * round_key: caller-owned AES128_ROUND_KEY_SIZE-byte buffer that receives all
 *            11 round keys concatenated (round n occupies bytes [n*16, n*16+16)).
 * Must be called once per key before any encrypt/decrypt/CTR call using that key.
 */
void aes128_key_expansion(const uint8_t key[AES128_KEY_SIZE],
                          uint8_t round_key[AES128_ROUND_KEY_SIZE]);

/*
 * aes128_encrypt_block - encrypt a single 16-byte block (raw AES-128, no mode).
 * round_key: output of aes128_key_expansion() for the key in use.
 * in:        16-byte plaintext block.
 * out:       caller-owned 16-byte buffer that receives the ciphertext block.
 * Not safe to use directly on messages longer than one block -- see
 * aes128_ctr_xcrypt() for that, and never reuse this alone as an encryption
 * mode (identical plaintext blocks always produce identical ciphertext blocks).
 */
void aes128_encrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

/*
 * aes128_decrypt_block - decrypt a single 16-byte block (inverse of aes128_encrypt_block).
 * round_key: output of aes128_key_expansion() for the key in use -- same round
 *            keys as encryption; the inverse round order is handled internally.
 * in:        16-byte ciphertext block.
 * out:       caller-owned 16-byte buffer that receives the plaintext block.
 */
void aes128_decrypt_block(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                          const uint8_t in[16], uint8_t out[16]);

/*
 * aes128_ctr_xcrypt - encrypt or decrypt a buffer of any length in CTR mode.
 * round_key:      output of aes128_key_expansion() for the key in use.
 * nonce_counter:  16-byte initial counter block. NOT MODIFIED by this call
 *                 (a local copy is incremented internally) -- pass the same
 *                 value again to decrypt what this call encrypted.
 * input, output:  may point to the same buffer (in-place) or different buffers.
 * length:         number of bytes to process; need not be a multiple of 16.
 * Encryption and decryption are the identical operation (XOR with a keystream).
 * Caller is responsible for never reusing the same (key, counter) pair for two
 * different messages -- see Cipher Modes Concepts for why that's catastrophic.
 */
void aes128_ctr_xcrypt(const uint8_t round_key[AES128_ROUND_KEY_SIZE],
                        const uint8_t nonce_counter[16],
                        const uint8_t *input,
                        uint8_t *output,
                        size_t length);
#endif // AES128_H

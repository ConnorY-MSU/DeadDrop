#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA256_DIGEST_SIZE 32

/*
 * hmac_sha256 - compute HMAC-SHA256(key, data) per RFC 2104, built entirely
 * on this project's own sha256_context (see sha256.h) -- no external crypto
 * library is involved in the HMAC computation itself.
 *
 * key:     the MAC key. May be any length (RFC 2104 5.a: keys longer than
 *          one SHA-256 block (64 bytes) are hashed down to 32 bytes first).
 * key_len: length of key in bytes.
 * data:    the message to authenticate.
 * data_len: length of data in bytes.
 * digest:  caller-owned 32-byte buffer that receives the MAC.
 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SHA256_DIGEST_SIZE]);

#endif // HMAC_H
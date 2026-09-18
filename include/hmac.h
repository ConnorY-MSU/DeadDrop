#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA256_DIGEST_SIZE 32

/* hmac_sha256 - compute HMAC-SHA256(key, data) per RFC 2104 using this project's own sha256_context; key may be any length (RFC 2104 5.a). */
void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SHA256_DIGEST_SIZE]);

#endif // HMAC_H
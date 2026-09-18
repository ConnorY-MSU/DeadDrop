#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>


typedef struct {
    uint32_t state[8]; /*current hash value*/
    uint64_t bitlen;    /*message length in bits*/
    uint8_t buffer[64];  /*partial block*/
    size_t buffer_len;   /*number of bytes in buffer*/
} sha256_context;

/* sha256_init - reset ctx to the FIPS 180-4 initial hash values; call before update()/final(), or to reuse a context. */
void sha256_init(sha256_context *ctx);

/* sha256_update - feed len bytes at data into an in-progress hash; may be called any number of times with any chunk sizes. */
void sha256_update(sha256_context *ctx, const uint8_t *data, size_t len);

/* sha256_final - pad, process the final block(s), and write the big-endian digest into caller-owned digest[32]; ctx must be re-init'd before reuse. */
void sha256_final(sha256_context *ctx, uint8_t digest[32]);

#endif /* SHA256_H */
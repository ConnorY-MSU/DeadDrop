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

void sha256_init(sha256_context *ctx);
void sha256_update(sha256_context *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_context *ctx, uint8_t digest[32]);

#endif /* SHA256_H */
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

/*
 * sha256_init - prepare a context for a new hash computation.
 * ctx: context to initialize. Must be called before any sha256_update()/sha256_final() call.
 * Resets state to the FIPS 180-4 initial hash values; safe to reuse a context by calling this again.
 */
void sha256_init(sha256_context *ctx);

/*
 * sha256_update - feed more message bytes into an in-progress hash.
 * ctx:  context previously initialized with sha256_init().
 * data: pointer to len bytes to absorb. May be called any number of times with any chunk sizes.
 * len:  number of bytes at data.
 * Precondition: ctx has been initialized (sha256_init) and not yet finalized (sha256_final).
 */
void sha256_update(sha256_context *ctx, const uint8_t *data, size_t len);

/*
 * sha256_final - apply padding, process the last block(s), and produce the digest.
 * ctx:    context with all message data already fed via sha256_update().
 * digest: caller-owned 32-byte buffer that receives the big-endian SHA-256 digest.
 * Precondition: ctx has been initialized. After this call, ctx must not be reused
 * without calling sha256_init() again first.
 */
void sha256_final(sha256_context *ctx, uint8_t digest[32]);

#endif /* SHA256_H */
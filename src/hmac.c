#include "hmac.h"
#include "sha256.h"
#include <string.h>

/* SHA-256's internal block size (FIPS 180-4 Sec. 4.2.2) -- also the block
 * size HMAC pads its key to, per RFC 2104. Not the same thing as the
 * digest size (32 bytes); this is deliberately a separate constant. */
#define HMAC_SHA256_BLOCK_SIZE 64

void hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t digest[HMAC_SHA256_DIGEST_SIZE])
{
    uint8_t key_block[HMAC_SHA256_BLOCK_SIZE];
    uint8_t ipad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t opad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t inner_digest[HMAC_SHA256_DIGEST_SIZE];
    sha256_context ctx;
    size_t i;

    /* RFC 2104 step 1/5.a: keys longer than one block are hashed down to
     * digest size first; keys shorter than one block are zero-padded out
     * to the full block. Either way key_block ends up exactly
     * HMAC_SHA256_BLOCK_SIZE bytes. */
    memset(key_block, 0, sizeof(key_block));
    if (key_len > HMAC_SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_block); /* fills first 32 bytes; rest stays 0 */
    } else {
        memcpy(key_block, key, key_len);
    }

    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
    }

    /* inner = H(ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof(ipad));
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_digest);

    /* outer = H(opad || inner) -- this is the HMAC result */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof(opad));
    sha256_update(&ctx, inner_digest, sizeof(inner_digest));
    sha256_final(&ctx, digest);

    /* Don't leave key material or intermediate state sitting in locals
     * longer than necessary. */
    memset(key_block, 0, sizeof(key_block));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
}
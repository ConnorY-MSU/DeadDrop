#include "sha256.h"
#include <string.h>

void sha256_transform(sha256_context *ctx, const uint8_t block[64]);

/* Initial hash values, FIPS 180-4 Sec. 5.3.3 -- fractional parts of the square
   roots of the first 8 primes ("nothing up my sleeve" numbers). */
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* Round constants, FIPS 180-4 Sec. 4.2.2 -- fractional parts of the cube
   roots of the first 64 primes. */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Bitwise primitives. Lowercase snake_case, matching the rest of the project
   (aes128.c's sub_bytes/shift_rows/etc.) rather than ALL-CAPS -- deliberate
   choice for consistency, since in C, ALL-CAPS conventionally signals a macro,
   not a real typed function like these. Names still map directly onto FIPS
   180-4's own notation: rotr = ROTR, ch = Ch, maj = Maj, bsig0/1 = Sigma0/1
   (uppercase sigma, used in the compression function), ssig0/1 = sigma0/1
   (lowercase sigma, used in the message schedule). */
static inline uint32_t rotr(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t bsig0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t bsig1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t ssig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t ssig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}


void sha256_init(sha256_context *ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void sha256_update(sha256_context *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8;
    while (len >0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sha256_final(sha256_context *ctx, uint8_t digest[32]) {
    uint8_t pad = 0x80; /* single '1' bit followed by zero bits, FIPS 180-4 Sec. 5.1.1 */
    uint64_t bitlen_be = ctx->bitlen; /* snapshot before update() calls below inflate it with padding bits */
    sha256_update(ctx, &pad, 1);
    static const uint8_t zero = 0;
    /* Pad with zero bytes until exactly 56 bytes (448 bits) are buffered, leaving
       the last 8 bytes of the 64-byte block for the length field below. Reusing
       update()'s buffering means this naturally spills into a second block when
       the message was already close to a block boundary -- see FIPS 180-4 Sec. 5.1.1. */
    while (ctx->buffer_len != 56) {
        sha256_update(ctx, &zero, 1);
    }
    uint8_t len_bytes[8]; /* original message length in bits, big-endian, per FIPS 180-4 Sec. 5.1.1 */
    for (int i =0; i < 8; i++) {
        len_bytes[i] = (uint8_t)(bitlen_be >> (56 - 8 * i));
    }
    memcpy(ctx->buffer + 56, len_bytes, 8);
    sha256_transform(ctx, ctx->buffer);
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256_transform(sha256_context *ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    for (int t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; t++) {
        W[t] = ssig1(W[t - 2]) + W[t - 7] + ssig0(W[t - 15]) + W[t - 16];
    }
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int t = 0; t < 64; t++) {
        uint32_t T1 = h + bsig1(e) + ch(e, f, g) + K[t] + W[t];
        uint32_t T2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

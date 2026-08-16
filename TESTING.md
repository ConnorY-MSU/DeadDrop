# TESTING.md — Running Test Log

Full, ongoing test log for `securelink`, started Week 1 Day 1 per project documentation standard. Entries are added incrementally as each component is built and validated — not rewritten after the fact.

---

## SHA-256 — Week 1, Day 1–2

### Status: Complete, all vectors passing

### Design decisions

**Incremental init/update/final API.** `sha256_init()` / `sha256_update()` / `sha256_final()` rather than a single one-shot `sha256(data, len, digest)` call. Chosen because the caller often doesn't have the entire message in memory at once (e.g. hashing a large file in chunks) — this mirrors the API shape used by OpenSSL, mbedTLS, and most production hash libraries, and sets up cleanly for HMAC later.

```c
typedef struct {
    uint32_t state[8];    // running hash value
    uint64_t bitlen;      // total message length seen so far, in bits
    uint8_t  buffer[64];  // holds a partial block between update() calls
    size_t   buffer_len;  // how many bytes are currently in buffer
} sha256_context;
```

**Header/implementation split.** `include/sha256.h` holds only the struct definition and three function prototypes. `src/sha256.c` holds the function bodies plus the internal-only constants (`H0`, `K`) and helper functions (`ROTR`, `CH`, `MAJ`, `BSIG0/1`, `SSIG0/1`) — none of which are exposed in the public header, since callers never need them directly. This was a real bug source during development: an earlier version had full function bodies in the header, which worked with a single source file but would have caused "multiple definition" linker errors the moment a second `.c` file (e.g. the test file) included the header.

**`static inline` functions instead of macros** for `ROTR`/`CH`/`MAJ`/`BSIG0`/`BSIG1`/`SSIG0`/`SSIG1`. Chosen over the more common macro-based style (seen in many reference implementations) for real type checking from the compiler and to avoid classic macro pitfalls (missing parens, double-evaluated arguments).

**Padding reuses `sha256_update()` internally.** `sha256_final()` appends the `0x80` pad byte and zero-fill bytes by calling `sha256_update()` byte-by-byte, rather than writing separate spillover-handling logic. Since `update()` already transforms and resets the buffer whenever it fills to exactly 64 bytes, this means the "does padding spill into a second block" boundary case (e.g. when the final partial block is already 57+ bytes) is handled automatically by the existing buffering logic, with no special-casing required. The original message's `bitlen` is captured into a local variable *before* the padding calls to `update()`, since those calls would otherwise inflate the tracked bit length with the padding bytes themselves.

### Test vectors

Three vectors, chosen deliberately to cover the boundary case that catches the most common implementation bugs: an empty message, a single-block message, and a message that forces two compression blocks.

| Input | Length | Expected digest (FIPS 180-4 / NIST) |
|---|---|---|
| `""` | 0 bytes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"abc"` | 3 bytes | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"` | 56 bytes | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |

The 56-byte vector is the important one: 56 bytes = 448 bits, which lands exactly on the padding boundary from FIPS 180-4 — the message itself doesn't fill a block, but once the `0x80` pad byte is appended there's no room left for the 64-bit length field in the same block, forcing a second, all-padding block. This is the same edge case traced by hand during design, and is what actually exercises the multi-block chaining path in `update()`/`final()`, as opposed to just the compression function in isolation.

### Test harness

`tests/test_sha256.c` — runs each vector through the real init/update/final pipeline and compares against the expected digest with `memcmp`.

### Actual run output

```
[PASS] empty string
[PASS] "abc" (single block)
[PASS] 56-byte message (forces two blocks)

ALL VECTORS PASSED
```

Compiled clean with `gcc -Wall -Wextra -g`, zero warnings, on the final build.

### Independent cross-validation

Checked the `"abc"` result against Windows' own built-in hashing (PowerShell `Get-FileHash`), independent of both the NIST-vector expected value and the project's own test harness:

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\abc_test.txt", "abc")
Get-FileHash "$env:TEMP\abc_test.txt" -Algorithm SHA256
```

```
Algorithm       Hash                                                             Path
---------       ----                                                             ----
SHA256          BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  C:\Users\yette\AppData\Local\Temp\abc_test.txt
```

Matches the implementation's output exactly (case difference only). Three-way agreement: NIST published vector, this project's own implementation, and an independent OS-level hasher.

### Bugs hit and how they were resolved

In the order encountered:

1. **`sha256.h` had function bodies instead of prototypes, and no include guard.** Fixed by splitting into declaration-only header + `src/sha256.c` implementation. Caught before it caused an actual link error, by reviewing the design against the project's own `src`/`include` convention.
2. **`sha256.c` was created inside `include/` instead of `src/`.** Cosmetic but broke the intended project layout; moved with `git mv`-equivalent relocation.
3. **Stray `#include "debug.h"` in `sha256.c`** pointed at a file that existed at the repo root, unreachable from the actual compiler include paths (`-Iinclude`, and `src/`'s own directory) — caused `fatal error: debug.h: No such file or directory`. It also wasn't actually used in the file. Removed.
4. **Typo: `lenbytes[i]` vs. the declared `len_bytes[8]`** in `sha256_final` — undeclared-identifier compile error. Fixed by correcting the variable name.
5. **`-Warray-parameter=` warning**: the header declared `sha256_final`'s second parameter as `uint8_t *hash`, while the `.c` file defined it as `uint8_t digest[32]`. Both are legal C and equivalent at the machine level, but modern GCC flags the mismatched array-bound annotation between a declaration and its definition. Fixed by aligning both to `uint8_t digest[32]`.
6. **`sha256_transform` called before being declared.** The function is defined at the bottom of `sha256.c` but called from `sha256_update`/`sha256_final` above it. On GCC 16.2.0 (which defaults to C23), an implicit function declaration is a **hard compile error**, not just a warning as in older C standards — required adding an explicit forward declaration near the top of the file.
7. **Environment-level blockers, not code bugs**: no C compiler was installed on the machine at all initially (VS Code's IntelliSense error pointed at this indirectly, and a `#include <studio.h>` typo along the way was a red herring on top of the real problem). Resolved by installing MSYS2 and the `mingw-w64-ucrt-x86_64-gcc` toolchain via `pacman`, then adding it to PATH and pointing VS Code's IntelliSense at it directly.

Notably: **the actual SHA-256 algorithm logic — the message schedule recurrence, the eight round functions, the round loop, and all 72 transcribed constants — was correct on the first attempt** and needed zero fixes once it compiled. Every bug above was either infrastructure (missing compiler, misconfigured editor) or a small mechanical slip (typo, file location, missing forward declaration), not a misunderstanding of the algorithm itself.

---

## AES-128 — Week 1, Day 3–4

### Status: Complete. Key expansion, single-block encryption, single-block decryption, and CTR mode are all implemented and independently validated.

### Design decisions

**Byte-oriented key schedule.** `aes128_key_expansion()` builds the full 176-byte round-key array (11 round keys × 16 bytes, for AES-128's 10 rounds) using a byte-indexed loop rather than a word-indexed (`uint32_t[44]`) one. Every 16 bytes — i.e. at each new round-key boundary — the last 4 bytes are rotated (`RotWord`), passed through the S-box (`SubWord`), and XORed with the round constant (`Rcon`) before being XORed against the corresponding bytes from the previous round key. Mathematically identical to the more commonly seen word-based schedule, just implemented at byte granularity.

**Round keys stored as a flat `uint8_t[176]` array** (`AES128_ROUND_KEY_SIZE`), rather than an `[11][16]` 2D array or a struct — round key `n` occupies bytes `n*16` through `n*16+15`. Kept consistent between `aes128_key_expansion()` and `aes128_encrypt_block()`.

**State representation: flat `uint8_t[16]`, column-major**, matching FIPS 197's own byte numbering. All four round operations (`sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key`) operate directly on this representation.

**Internal helpers kept `static`; only the two functions a caller actually needs are exposed** in `aes128.h` — `aes128_key_expansion()` and `aes128_encrypt_block()`. `sbox`, `rcon`, `xtime()`, `sub_bytes()`, `shift_rows()`, `mix_columns()`, `add_round_key()` are all file-local implementation details, same header/implementation split reasoning as SHA-256's constants and helper functions.

**Round structure**: an initial `AddRoundKey` (round 0) before the loop, rounds 1–9 run SubBytes → ShiftRows → MixColumns → AddRoundKey, and round 10 omits MixColumns, per the spec's final-round exception.

**Decryption uses the straightforward `InvCipher` structure from FIPS 197 §5.3**, not the "Equivalent Inverse Cipher" optimization — `AddRoundKey(10)` first, then for rounds 9 down to 1: `InvShiftRows → InvSubBytes → AddRoundKey(round) → InvMixColumns`, then a final `InvShiftRows → InvSubBytes → AddRoundKey(0)` with no `InvMixColumns` after it. Derived by literally inverting the encrypt function step-by-step (reverse the order, invert each operation, keep `AddRoundKey` as-is since XOR is its own inverse) rather than copying the spec's pseudocode directly.

**`inv_sbox` transcribed separately from FIPS 197 Figure 14**, then verified against the already-validated forward `sbox` (spot-checked, not derived from it programmatically) — both tables independently confirmed correct against the spec, byte for byte.

**A general GF(2⁸) multiplier (`gmul`)**, built from repeated `xtime` calls using the standard "Russian peasant multiplication" pattern, rather than only the specific ×2/×3 combinations `mix_columns` needed. This generalizes cleanly to `inv_mix_columns`'s larger constants (0x09, 0x0b, 0x0d, 0x0e) without needing separate hardcoded multiply functions per constant.

**CTR mode (`aes128_ctr_xcrypt`)**: encrypts a 16-byte counter block with `aes128_encrypt_block` (never the decrypt path — CTR only ever uses the forward cipher, on the counter, not on the data) to produce a keystream block, XORs it against up to 16 bytes of input/output, and increments the counter before the next chunk. The final chunk of a non-block-aligned input still generates a full 16-byte keystream block internally but only consumes as many bytes as remain — handles arbitrary-length input without padding, by design. Encrypt and decrypt are the literal same function call.

**Counter increment (`increment_counter`)**: a full 128-bit big-endian increment with carry propagation across all 16 bytes (start at byte 15, carry left on overflow), rather than only incrementing a 32-bit tail with a fixed nonce prefix. A legitimate alternative per SP 800-38A Appendix B's "standard incrementing function," which permits applying the increment to the whole block or just part of it.

### Test vectors

| Test | Key | Input | Expected |
|---|---|---|---|
| FIPS-197 Appendix B encrypt | `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `69c4e0d86a7b0430d8cdb78070b4c55a` |
| FIPS-197 Appendix B decrypt | (same key) | `69c4e0d86a7b0430d8cdb78070b4c55a` | `00112233445566778899aabbccddeeff` |
| SP 800-38A F.1.1 ECB-AES128 encrypt | `2b7e151628aed2a6abf7158809cf4f3c` | `6bc1bee22e409f96e93d7e117393172a` | `3ad77bb40d7a3660a89ecaf32466ef97` |
| SP 800-38A F.1.1 ECB-AES128 decrypt | (same key) | `3ad77bb40d7a3660a89ecaf32466ef97` | `6bc1bee22e409f96e93d7e117393172a` |
| SP 800-38A F.5.1 CTR-AES128, 4 blocks | `2b7e151628aed2a6abf7158809cf4f3c`, initial counter `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` | 4 blocks of plaintext (see SP 800-38A Appendix F) | `874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee` |

Two independent official NIST sources (FIPS 197 and SP 800-38A), different keys, both directions, plus a full 4-block CTR run against the spec's own worked example.

### Test harness

`tests/test_aes128.c` — same `hex_to_bytes`/`check_block` pattern as `test_sha256.c`, reusing `debug.c`'s `print_hex`. Beyond the spec vectors, it also includes:
- A round-trip test (encrypt then decrypt, confirm original bytes recovered) for both the single-block cipher and CTR mode
- A CTR round-trip on a deliberately **non-block-aligned length (37 bytes)** — this is the case that actually exercises the partial-final-block logic in `aes128_ctr_xcrypt`, since all the spec vectors happen to be exact multiples of 16 bytes
- An **ECB demonstration**: two identical 16-byte plaintext blocks, encrypted independently with raw `aes128_encrypt_block` (no mode), confirming identical ciphertext blocks — reproducing the mechanism behind the "ECB penguin" directly rather than just describing it

### Actual run output

```
[PASS] FIPS-197 Appendix B single-block encrypt
[PASS] FIPS-197 Appendix B single-block decrypt
[PASS] Round-trip: encrypt then decrypt returns original plaintext
[PASS] NIST SP800-38A F.1.1 block #1 encrypt
[PASS] NIST SP800-38A F.1.1 block #1 decrypt
[PASS] SP800-38A F.5.1 CTR block 1
[PASS] SP800-38A F.5.1 CTR block 2
[PASS] SP800-38A F.5.1 CTR block 3
[PASS] SP800-38A F.5.1 CTR block 4
[PASS] CTR round-trip: decrypt(encrypt(P)) == P
[PASS] CTR round-trip on non-block-aligned length (37 bytes)
[PASS] ECB demonstration: identical plaintext blocks produce identical ciphertext blocks
  plaintext block A : 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
  plaintext block B : 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
  ciphertext block A: 35 d1 4e 6d 3e 3a 27 9c f0 1e 34 3e 34 e7 de d3
  ciphertext block B: 35 d1 4e 6d 3e 3a 27 9c f0 1e 34 3e 34 e7 de d3

ALL VECTORS PASSED
```

Compiled clean with `gcc -Wall -Wextra -g`, zero warnings.

### Bugs hit and how they were resolved

1. **Stray code pasted at file scope in `aes128.c`.** A block of test/usage-style statements (calling `aes128_key_expansion` and the not-yet-written `aes128_ctr_xcrypt` on undeclared variables) ended up sitting directly between two function definitions in the source file, outside any function body — not valid C. Actual compiler output: `error: conflicting types for 'aes128_key_expansion'; have 'int()'`, since a statement at file scope with no type is interpreted as an implicit-int function declaration. Removed; the calls belonged in the test file, not the implementation file.
2. **`aes128_ctr_xcrypt` was declared in the header and "called" before it was ever implemented** — the function body didn't exist anywhere. Not really a bug so much as building top-down (interface first) rather than bottom-up; resolved by writing the actual implementation.

Notably, once both of those were sorted out, **every actual algorithm decision — the `InvCipher` round sequence, `gmul`, the counter increment, the partial-block handling — was correct on the first compiled attempt**, proven against official vectors rather than just assumed.

### Next up
- AES-128 core is complete: encrypt, decrypt, a cipher mode, and the ECB failure demonstration are all done and validated
- Remaining Day 5 items (Valgrind/ASan, code cleanup, Encrypt-then-MAC write-up, commit hygiene review) per [[01-Week 1 - Crypto Foundations/Week 1 Day 5 Walkthrough|Week 1 Day 5 Walkthrough]]

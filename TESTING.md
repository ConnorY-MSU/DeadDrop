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

---

## Week 1, Day 5 — Hardening, cleanup, and write-up

### Status: Complete. Week 1 is fully closed out.

### Sanitizer results

Valgrind isn't available on native Windows without WSL. Used AddressSanitizer + UndefinedBehaviorSanitizer instead, per [[01-Week 1 - Crypto Foundations/Week 1 Day 5 Walkthrough|Week 1 Day 5 Walkthrough]]'s guidance for this exact situation.

One real environment finding along the way: **GCC's MinGW build on Windows has no sanitizer runtime at all** — `-fsanitize=address`/`-fsanitize=undefined` fail to link (`cannot find -lasan`). Installed a separate Clang toolchain via MSYS2 (`clang64` environment) specifically for this, since Clang's Windows ASan/UBSan support is considerably more mature than GCC's MinGW port.

Both test binaries rebuilt and run under Clang with `-fsanitize=address -fsanitize=undefined`:

```
test_sha256.exe: [PASS] empty string / [PASS] "abc" / [PASS] 56-byte message — ALL VECTORS PASSED
test_aes128.exe:  all 12 checks PASS — ALL VECTORS PASSED
```

**Zero memory-safety or undefined-behavior findings on either binary.**

### Code review pass

Per the Documentation Standard, reviewed both `.c` files and both headers for magic numbers, naming consistency, and missing function documentation:

- **Function-header docs added** to every public function in `sha256.h` and `aes128.h` — purpose, parameters, return value, preconditions.
- **Magic numbers explained**: `0x1B` in `xtime` (AES reduction polynomial, FIPS 197 Sec. 4.2 — flagged as a to-do back on Day 3 and finally addressed here), the InvMixColumns matrix constants (`0x0e`/`0x0b`/`0x0d`/`0x09`), `H0`/`K`'s FIPS 180-4 citations, and the `0x80`/`56`-byte padding boundary in `sha256_final`.
- **Naming inconsistency found and fixed**: `sha256.c`'s helper functions (`ROTR`, `CH`, `MAJ`, `BSIG0/1`, `SSIG0/1`) were ALL-CAPS while everything else in the project is snake_case — inconsistent with C convention, where ALL-CAPS conventionally signals a macro, not a real function. Renamed to `rotr`/`ch`/`maj`/`bsig0/1`/`ssig0/1`, with a comment mapping each back to FIPS 180-4's own Σ₀/Σ₁/σ₀/σ₁/Ch/Maj notation so the spec cross-reference isn't lost.
- **`debug.c`/`debug.h` relocated** into `src/`/`include/` — flagged as a lingering layout inconsistency since Day 1, finally fixed.

Rebuilt and re-ran both full test suites after every change in this pass; all vectors continued to pass throughout.

### Write-up: Encrypt-then-MAC

For MAC-then-Encrypt you must decrypt (run padding/parsing logic) before you can check the MAC, so attacker-forged ciphertext reaches your complex decryption code, and any signal about *why* decryption failed (bad padding vs bad MAC) becomes an oracle to decrypt data byte-by-byte (e.g., POODLE).

For Encrypt-then-MAC you verify the MAC over the raw ciphertext first. Forged data gets rejected immediately, and it never touches your decryption/padding logic at all.

Bottom line: verify-before-decrypt means only a simple, fixed MAC check ever runs on untrusted bytes; the riskier decryption code only ever sees data already proven authentic.

### NIST vectors tested this week (full citation list)

| Component | Source | Vectors |
|---|---|---|
| SHA-256 | FIPS 180-4 | Empty-string, `"abc"`, and a 56-byte two-block message |
| SHA-256 | Independent cross-check | Windows `Get-FileHash` (PowerShell, SHA-256) |
| AES-128 encrypt/decrypt | FIPS 197 Appendix B | Single official worked example, both directions |
| AES-128 encrypt/decrypt | NIST SP 800-38A Appendix F.1.1 (ECB-AES128) | Independent key, both directions |
| AES-128 CTR mode | NIST SP 800-38A Appendix F.5.1 (CTR-AES128) | All 4 blocks against the spec's own worked example |

### Commit hygiene check

`git log --oneline` reviewed end-to-end: every commit is small, scoped to one logical change, and clearly labeled (scaffold → SHA-256 impl → tests → docs → AES impl → tests → docs → decrypt/CTR → tests → docs → cleanup). No giant dumps, nothing needing history rewrites.

### Week 1 — closed

SHA-256 and AES-128 (encrypt, decrypt, CTR mode) are complete, independently validated against multiple official NIST sources, clean under sanitizers, documented, and committed. Per [[00-Start Here/Four-Week Roadmap|Four-Week Roadmap]]'s End of Week 1 gate: all three checkpoints met — SHA-256 passes all tested vectors including a multi-block message, AES-128 passes FIPS-197 Appendix B plus an independent KAT, and the Encrypt-then-MAC reasoning above is written from understanding, not paraphrased.

---

## Week 2, Day 1 — wolfSSL build

### Status: Complete. wolfSSL built from source, installed, and verified working with a real TLS 1.3 handshake.

### Environment notes

Full rationale in `docs/BUILD.md`. Summary: built under MSYS2's **UCRT64** environment specifically (not plain MSYS, not raw PowerShell) so the resulting library links cleanly against the same toolchain the rest of this project already uses. Required installing `autoconf`/`automake`/`libtool` (for the autotools build itself) and a separate `git` inside MSYS2 (which doesn't inherit the Windows PATH, so Week 1's Git for Windows install is invisible to it).

### Build configuration

```
./configure --enable-static --disable-shared --enable-debug --prefix=/ucrt64
```

Verified against this exact checkout's real `./configure --help` output rather than assumed — static-only build (avoids a runtime-DLL-discovery problem, same category as Week 1's ASan DLL issue), debug symbols on, installed directly into the existing UCRT64 toolchain's search path. `--enable-tls13` was **not** needed — confirmed already the default in current wolfSSL (`--disable-tls13` is the flag that exists to turn it off).

### Verification

Confirmed via `Test-Path`: `C:\msys64\ucrt64\include\wolfssl\` and `C:\msys64\ucrt64\lib\libwolfssl.a` both present after `make install`.

**Real functional proof** — wolfSSL's own bundled example client/server, run against each other over loopback with TLS 1.3 explicitly forced (`-v 4`), output captured to separate files:

```
client_out.txt: SSL version is TLSv1.3 / I hear you fa shizzle!
server_out.txt: SSL version is TLSv1.3 / Client message: hello wolfssl!
```

A genuine handshake, both sides agreeing on TLS 1.3, message exchanged in both directions — not just "it compiled." (First attempt, without `-v 4`, negotiated TLS 1.2 by default — proved the build works, but not the actual TLS-1.3 requirement specifically; re-ran with the version forced to get real proof of the thing that matters.)

### Bugs hit and how they were resolved

1. **`configure: error: no acceptable C compiler found in $PATH`** despite gcc being installed — root cause: invoking MSYS2's bash directly (`usr/bin/bash.exe`) uses the base MSYS environment's PATH, which doesn't include the UCRT64 compiler. Fixed by explicitly setting `MSYSTEM=UCRT64` and sourcing `/etc/profile` before running `configure`.
2. **`autoreconf: command not found`** on the first `./autogen.sh` attempt — `autoconf`/`automake`/`libtool` weren't installed yet (Week 1 only installed the compiler, not the autotools). Installed via `pacman`.
3. **`fatal: repository '' does not exist`** on the very first `git clone` attempt — an empty argument reached git, most likely from a copy-paste whitespace artifact (a double space between `clone` and the URL). Re-ran the clone cleanly rather than debugging the exact shell-parsing cause.
4. **Shell scripting bug, not a wolfSSL problem**: `cd dir && server.exe &` backgrounds the *entire* `cd && server` compound as one subshell — the `cd` never affected the main shell, so a following command using a relative path failed with "No such file or directory". Fixed by putting `cd` on its own line and backgrounding only the server command, capturing its PID via `$!` for cleanup instead of relying on job-control (`%1`) syntax.
5. **Garbled/interleaved output** on the first client+server test — both processes were redirected to the same output file, and concurrent writes interleaved character-by-character into unreadable text. Fixed by redirecting each process to its own file.

Notably: every bug above was environment/tooling/shell-scripting, not a wolfSSL configuration or usage mistake — the actual wolfSSL build and API usage worked correctly once the surrounding mechanics were sorted out.

---

## Week 2, Day 2 — PKI setup

### Status: Complete. CA, server cert, and client cert generated and fully verified. Revocation-check module built and tested.

### Design decisions

**PKI files stored entirely outside any git repository**, at `C:\Users\yette\securelink-pki` — not even gitignored inside a repo, since physical separation avoids the "one `git add -f` away from a leaked key" failure mode a `.gitignore` entry doesn't fully protect against. Also confirmed outside OneDrive's sync scope (OneDrive is scoped to `C:\Users\yette\OneDrive\` specifically on this machine — verified via the registry's `User Shell Folders` keys before choosing the location, not assumed).

**Folder-level NTFS permissions restricted** via `icacls` (inheritance removed, access granted only to the local account and `SYSTEM`) *before* any files were created inside it, so every file inherits the restriction automatically.

**CA key passphrase-protected (`-aes256`, RSA 4096); server/client keys left unencrypted (RSA 2048).** Deliberate asymmetry: the CA key never needs unattended access and its compromise would be catastrophic (ability to forge trust for anything), so a passphrase is pure upside. The device keys will eventually need to load automatically on an unattended Pi (Week 4's zero-touch-boot requirement), so a passphrase there would be a real conflict, not just an inconvenience — same reasoning already established for the hardware-backed key storage decision.

**Distinct, deliberately different Common Names** for the CA (`SecureLink Root CA`) vs. server (`SecureLink-Server`) vs. client (`SecureLink-Client`) — guards against the CN-mixup class of mistake flagged in [[02-Week 2 - TLS and mTLS/X.509 and PKI Concepts|X.509 and PKI Concepts]]' common-mistakes list.

### Verification performed

Full detail and exact commands in `docs/PKI_SETUP.md`. Summary:

| Check | Method | Result |
|---|---|---|
| Key encryption | `head -2 <key>.pem`, inspect PEM header | CA: `ENCRYPTED PRIVATE KEY` ✓ / server, client: plain `PRIVATE KEY` ✓ |
| Subject/issuer/serial/validity | `openssl x509 -noout -subject -issuer -serial -dates` | All three correct — see table in `docs/PKI_SETUP.md` |
| Serial uniqueness | Compared serials directly | Sequential and distinct (`...83F8`, `...83F9`) — required for the revocation check |
| File permissions | `chmod 600`, then verified via `icacls` (not `ls -la`) | Correctly restricted to owning user + SYSTEM only |
| **Cryptographic chain validity** | `openssl verify -CAfile ca_cert.pem <cert>.pem` | `server_cert.pem: OK`, `client_cert.pem: OK` — proves the signatures are actually valid, not just that the issuer field contains the right string |

### Bugs hit and how they were resolved

1. **Passphrase prompt appeared where it shouldn't have (Step 4, generating the server CSR).** Root cause: nearly certainly a copy-paste/typo referencing `ca_key.pem` instead of `server_key.pem` in the command (the two commands look similar). Diagnosed by directly inspecting `server_key.pem`'s actual PEM header (`-----BEGIN PRIVATE KEY-----`, no `ENCRYPTED` marker) to confirm the file itself was correctly unencrypted before concluding the mistake was in the command, not the key generation step.
2. **`chmod 600` appeared not to work** — `ls -la` continued showing `-rw-r--r--` (644) after running it. Root cause: MSYS2's `chmod`/`ls -la` on an NTFS filesystem is a POSIX-permission *emulation* layer that doesn't map 1:1 onto real Windows ACLs. The actual enforced permission (verified via `icacls`, the authoritative source on Windows) was already correctly restricted, inherited from the folder-level lockdown set up before the files existed. Not a real bug — a display-layer discrepancy worth knowing about for any future Windows/MSYS2 permission check.

### Revocation-check module (`src/revocation.c` / `include/revocation.h`)

**Design**: revoked serials stored one-per-line in a plain text file, in the exact hex format `openssl x509 -noout -serial` already outputs — revoking a cert in practice is just running that command and pasting the result in. Public interface: `revocation_load(filepath)`, `revocation_is_revoked(serial_hex)`, `revocation_free()`.

**Real security decisions made, not just plumbing:**
- **Fails closed** — before `revocation_load()` is ever called, after `revocation_free()`, on a `NULL` input, or if the list file fails to load: every check returns "revoked" rather than silently trusting an unverified state. Deliberately the safer default for a security check.
- **Case-insensitive by normalization** — both the stored list and every query are uppercased before comparing, rather than relying on a case-insensitive compare function at check time. Keeps the in-memory list in one consistent format.
- **Bounds-checked loading** — a fixed `MAX_REVOKED_SERIALS` capacity with a warning (not a silent overflow) if exceeded; `MAX_SERIAL_LEN` sized with real margin above the RFC 5280 max serial length (20 bytes = 40 hex chars).
- Every `strncpy` call is followed by explicit null-termination — the specific gotcha `strncpy` doesn't handle on its own.

**Test harness** (`tests/test_revocation.c`) — validated against real certificate serials from `docs/PKI_SETUP.md`, not synthetic data:

```
[PASS] fails closed before revocation_load() is called (got 1, expected 1)
[PASS] revocation_load() succeeds on a valid file (got 0, expected 0)
[PASS] revoked serial (server) is detected as revoked (got 1, expected 1)
[PASS] non-revoked serial (client) is NOT flagged as revoked (got 0, expected 0)
[PASS] case-insensitive match (lowercase input) (got 1, expected 1)
[PASS] NULL input fails closed (got 1, expected 1)
[PASS] fails closed again after revocation_free() (got 1, expected 1)
[PASS] revocation_load() fails cleanly on a missing file (got -1, expected -1)

ALL VECTORS PASSED
```

Compiled clean with `gcc -Wall -Wextra -g`, zero warnings.

### Next up
- Week 2 Day 2 is fully complete
- Wire `revocation_is_revoked()` into wolfSSL's verify callback (Week 2 Day 3) — today's work was deliberately kept standalone/testable so Day 3's integration is plumbing, not new logic

## Week 2, Day 3 — mTLS server

### Status: Complete. `src/server.c` implements raw TCP setup, wolfSSL context/cert/CA loading, mandatory client-cert verification, a custom verify callback wired to the Day 2 revocation module, and a minimal post-handshake read/log. All seven planned verification phases passed against real project certs and real serial numbers — not just "it compiled."

### Design decisions

**CLI arguments instead of hardcoded paths** (`-c`/`-k`/`-A`/`-r` for server cert, server key, CA cert, and revoked-serials file). Originally hardcoded absolute paths were fixed early once flagged as a Week 4 deployment blocker — the same binary now runs unmodified against different cert paths per device via a systemd unit's `ExecStart=` arguments, no rebuild needed.

**Mandatory client-cert verification**: `wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, my_verify_callback)`. `WOLFSSL_VERIFY_PEER` alone only verifies a cert *if offered*; adding `WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT` makes presenting one mandatory — this is the specific flag combination Day 5's "no client cert" negative test depends on.

**Trust scoped to exactly one CA**: `wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL)` loads only the project's own `ca_cert.pem`, nothing else. No system trust store is ever loaded. Verified concretely, not just by inspection (see Phase 5 below).

**Custom verify callback design**: fails closed on every path — if wolfSSL's own chain verification already set `preverify_ok = 0`, the callback returns 0 immediately without even attempting revocation logic (no point checking revocation status of a cert that's already untrusted). Only once the chain itself is confirmed valid does it extract the serial number and check it against the Day 2 revocation module. This ordering matters: it means the two rejection reasons ("wrong CA" vs. "revoked") are cleanly distinguishable in the logs, which Phase 5 and Phase 6 below both depend on to prove they're testing what they claim to be testing.

**`fflush(stdout)` after every log line the accept loop or verify callback prints.** Discovered mid-testing that `setvbuf(stdout, NULL, _IOLBF, 0)` (line-buffering) is silently ignored by MinGW/UCRT's C runtime whenever stdout isn't an actual console (e.g. redirected to a file or piped) — a known Windows CRT quirk, not specific to this project. Without explicit `fflush()`, log lines sat in an unflushed buffer and were lost entirely if the process was killed rather than exited cleanly, which made the server look like it wasn't doing anything even though it was working correctly. Explicit `fflush()` is the fix that actually works on Windows; this also matters for real deployed behavior later, not just today's testing, since prompt log visibility matters for a long-running service.

### The wolfSSL rebuild — a real, multi-layered build-environment problem

Writing the verify callback (`wolfSSL_X509_STORE_CTX_get_current_cert`, `wolfSSL_X509_get_serial_number`) surfaced that Day 1's wolfSSL build was missing wolfSSL's OpenSSL-compatibility layer (`OPENSSL_EXTRA`), which those two functions live behind. Confirmed definitively before doing anything — not assumed — via `nm libwolfssl.a | grep <function>`, which showed the symbols simply didn't exist as compiled code, and via `grep OPENSSL_EXTRA wolfssl/options.h`, which showed the flag wasn't defined in Day 1's build at all.

Fixing this took four distinct, separately-diagnosed problems, each confirmed with real evidence before moving to the next:

1. **Missing flag** — `--enable-opensslextra` wasn't part of Day 1's `./configure` line, since there was no way to know cert-introspection functions would be needed before this point. Fix: add the flag.
2. **`config.status: error: Something went wrong bootstrapping makefile fragments`** — the reconfigure's own internal dependency-tracking bootstrap step failed because `config.status` spawns a bare subshell that calls `make` without the full PATH our login shell has, giving `make: command not found` *inside configure itself*. This corrupted the resulting `libtool` script (it fell back to a stale/incorrect archiver command, `lib -OUT:...` — the MSVC-style syntax, not GNU `ar`). Fix: `--disable-dependency-tracking` plus a full `make distclean` to clear the corrupted intermediate state before reconfiguring — the clean reconfigure produced a correct `libtool` (`$AR $AR_FLAGS ...`) with no further intervention needed.
3. **The `Bash` tool available in this environment is Git Bash, not MSYS2's bash** — it inherits the persistent Windows PATH (so `gcc` in `ucrt64/bin` was found, since that was added to PATH in Week 1), but not MSYS2's `usr/bin` (where `make.exe`/`ar.exe`/`nm.exe` actually live). Every build step had to go through `C:\msys64\usr\bin\bash.exe -lc "export MSYSTEM=UCRT64; source /etc/profile; ..."` explicitly — the same pattern already established on Day 1, just re-confirmed the hard way after assuming a plain shell command would work.
4. **`make`/`make install` failed linking wolfSSL's own internal test suite** (`tests/unit.test.exe`), not our code — `undefined reference to wolfSSL_ERR_print_errors`. Traced to the actual definition in `wolfssl/wolfcrypt/logging.h`: that function requires `WOLFSSL_HAVE_ERROR_QUEUE`, which is gated `#if (defined(OPENSSL_EXTRA) && !defined(_WIN32) && ...)` — deliberately excluded on Windows by wolfSSL upstream, regardless of `OPENSSL_EXTRA`. This only affects wolfSSL's own bundled unit tests, which this project never uses; `libwolfssl.la`/`.a` and both example binaries (`client.exe`, `server.exe`) had already linked successfully before this failure. Fix: installed only what's actually needed — `make install-nobase_includeHEADERS` (headers, doesn't touch the `tests/` subdirectory) plus a direct copy of the freshly-built `src/.libs/libwolfssl.a` into `/ucrt64/lib/`, bypassing the recursive `make install` entirely rather than chasing down an unrelated upstream test-suite gap.

After all four fixes, `nm /ucrt64/lib/libwolfssl.a | grep wolfSSL_X509_STORE_CTX_get_current_cert` and the equivalent for `wolfSSL_X509_get_serial_number` both confirmed the real compiled symbols were present, and `src/server.c` compiled clean (`gcc -Wall -Wextra -g`, zero warnings) against the rebuilt library.

### Verification — all seven planned phases, each with real evidence

**Phase 1 (raw TCP accept)** — confirmed via the server's own log: `Raw TCP client connected.` printed on every connection attempt, before any TLS logic runs.

**Phase 2 (cert/key/CA loading)** — confirmed on Day 1 already; re-confirmed here as a byproduct of every later phase succeeding (a load failure would have prevented the context from ever reaching `wolfSSL_accept`).

**Phase 3 (mandatory verify mode)** — no standalone test; folded into Phase 4/5's pass/fail results below, which wouldn't be distinguishable without it.

**Phase 4 (full mTLS handshake, real project certs)** — ran wolfSSL's own proven example client against the server, pointed explicitly at this project's real certs:
```
./examples/client/client.exe -h 127.0.0.1 -p 4433 -c client_cert.pem -k client_key.pem -A ca_cert.pem -v 4
```
Server log:
```
Raw TCP client connected.
Verify callback: checking serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 against revocation list.
Verify callback: serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 not revoked, proceeding.
mTLS handshake succeeded.
Client message: hello wolfssl!
```
Client confirmed `SSL version is TLSv1.3`, `SSL cipher suite is TLS_AES_256_GCM_SHA384`, and `Verified Peer's cert` — a genuine, complete TLS 1.3 mutual handshake, both directions, real certs.

**Phase 5 (trust-scoping — must reject a cert that isn't ours, even if it's validly signed by *some* CA)** — ran the same client, but substituted wolfSSL's own bundled default client cert (`./certs/client-cert.pem`, signed by wolfSSL's own bundled CA, not ours) while keeping `-A` pointed at our real CA so the client would still trust our server correctly. Server log:
```
Raw TCP client connected.
```
stderr:
```
Verify callback: standard cert-chain verification failed.
Handshake failed: certificate verify failed
```
This is the exact result the check exists to produce: `preverify_ok` was 0 before the callback's own logic even ran, meaning wolfSSL's own chain verification rejected the cert — proving the server's trust is scoped to *only* the project's CA, not a broader default store that would have accepted wolfSSL's bundled cert.

**Phase 6 (revocation, both directions)**:
- Added the real client cert's actual serial (`68A7E95F14813C60A047706956F72BA0CCCC83F9`) to `revoked_serials.txt`, restarted the server (the list only loads at startup), reran the *same* previously-successful Phase 4 command. Server log:
  ```
  Raw TCP client connected.
  Verify callback: checking serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 against revocation list.
  ```
  stderr:
  ```
  Verify callback: serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 is REVOKED - rejecting.
  Handshake failed: verify problem on certificate
  ```
  Distinct rejection reason from Phase 5's — this cert's chain was completely valid (correct CA, correct signature); only the revocation check failed it. That distinction is what actually proves the Day 2 revocation module is wired in and doing something, not just present in the code.
- Removed the serial, restarted the server, reran the same command again: succeeded exactly as in Phase 4 (`mTLS handshake succeeded.` / `Client message: hello wolfssl!`) — confirms revocation is a live, reloadable check, not a permanent lockout once triggered.

**Phase 7 (post-handshake read)** — `Client message: hello wolfssl!` appears in every successful-handshake server log above, confirming `wolfSSL_read` correctly receives and the server correctly logs the client's application data. (By design, the server logs but doesn't echo — the client's own subsequent `SSL_read` then fails with "connection closed," which is expected client-side behavior given the server's logging-only design, not a bug.)

### Bugs hit and how they were resolved
1. The four wolfSSL-rebuild issues detailed above (missing flag, corrupted `libtool` from a failed dependency-tracking bootstrap, Git-Bash-vs-MSYS2-bash PATH confusion, and wolfSSL's own Windows-excluded error-queue feature breaking only its own unrelated test suite).
2. `setvbuf(_IOLBF)` silently ignored by Windows' C runtime for non-console output — replaced with explicit `fflush()` after each log line, which does work reliably.
3. First trust-scoping test attempt was constructed backwards (swapped which side's CA mismatch was being tested), causing a client-side rejection of the *server's* cert instead of the intended server-side rejection of the *client's* cert. Caught by reading the actual client-side error output carefully rather than just checking the exit code, and re-run correctly.

### Next up
- Week 2 Day 3 is complete
- Day 4: write `client.c`, the mirror of everything above from the client role — should go faster, all the mechanics are now familiar
- Day 5: the four formal negative tests (no cert, wrong CA, expired, revoked) for `TESTING.md` — Phases 5 and 6 above are functionally rehearsals for two of these already

## Week 2, Day 4 — mTLS client

### Status: Complete. `src/client.c` implements socket connect, wolfSSL client context/cert/CA loading, server-cert verification, the handshake, and a minimal application-data send. Full round-trip proven against the project's own `server.c` — not wolfSSL's bundled example client standing in for it.

### Design decisions

**Client-side verify mode: `wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL)`, deliberately without `WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT`.** That flag makes cert presentation *mandatory* for whichever side is being verified — but a TLS server always sends its certificate as part of the protocol regardless, so on the client side it would be a no-op, not a meaningful hardening. Reasoned through explicitly rather than copy-pasted from `server.c`'s (correctly different) verify-mode call.

**No `wolfSSL_read` after sending the message.** `server.c` is designed to log the client's message, not echo one back — so a client that waits to read a reply would just hit "connection closed" once the server closes the socket, exactly what happened when wolfSSL's own example client was used against this server on Day 3. Deliberately not repeating that here; the client just sends and exits cleanly.

**Host/port kept as generic defaults (`127.0.0.1:4433`), but cert/key/CA paths are required arguments with no default** — same reasoning as `server.c`'s CLI-args fix, applied consistently this time. Host/port aren't tied to any one machine; a hardcoded absolute cert path is. Missing `-c`/`-k`/`-A` now prints a usage message and exits 1, rather than silently falling back to a path that only exists on one developer's machine.

### A real mistake caught and fixed before this was "done"

While writing `client.c`, its content was accidentally saved into `src/server.c` instead — overwriting the working, committed Day 3 server with client-only logic, and leaving no `client.c` file on disk at all. Caught immediately by actually reading the file back rather than assuming the save landed correctly. Since nothing had been committed on top of the accidental overwrite, recovery was a two-step, zero-risk fix: `git checkout HEAD -- src/server.c` to restore the real server unchanged, then save the client code to its actual file, `src/client.c`. Confirmed the restore was genuine (not just "no error") by grepping the restored file for server-only symbols (`my_verify_callback`, `wolfTLSv1_3_server_method`, `accept(`) before trusting it.

This is exactly why committing at every real checkpoint (established habit since Week 1) matters beyond just "backup" — it turned what could have been a lost afternoon of work into a two-command fix.

### Verification

**Compiled clean**, `gcc -Wall -Wextra -g`, zero warnings, against the same rebuilt wolfSSL from Day 3.

**Missing-args path tested on both binaries** — confirms the hardcoded-path fix actually works, not just compiles:
```
$ ./build/server.exe
Usage: .../server.exe -c <server_cert.pem> -k <server_key.pem> -A <ca_cert.pem> -r <revoked_serials.txt>
...

$ ./build/client.exe
Usage: .../client.exe -c <client_cert.pem> -k <client_key.pem> -A <ca_cert.pem> [-h <host>] [-p <port>]
...
```
Both exit 1, neither silently falls back to a machine-specific path.

**The actual milestone — two custom binaries, not one custom plus wolfSSL's example client:**

Client output:
```
wolfSSL initialized; cert/key/CA loaded from client_cert.pem / client_key.pem / ca_cert.pem
Connected to server.
mTLS handshake succeeded.
Sent: hello from client.c
```

Server output:
```
Raw TCP client connected.
Verify callback: checking serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 against revocation list.
Verify callback: serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 not revoked, proceeding.
mTLS handshake succeeded.
Client message: hello from client.c
```

The server printing `hello from client.c` verbatim — not wolfSSL's canned `hello wolfssl!` — is the actual proof this is genuinely two pieces of this project's own code completing a full TLS 1.3 mutual handshake with each other, real certs, real revocation check, zero errors on either side. Re-verified identically after the hardcoded-path fix above, confirming the fix didn't regress anything.

### Bugs hit and how they were resolved
1. Client code accidentally saved to `src/server.c` instead of `src/client.c` — caught and fixed as detailed above, no data actually lost since it had never been committed.
2. Both binaries still had the Day-3-flagged-but-unresolved hardcoded absolute-path fallback issue; fixed properly this time in both files together rather than leaving it open again.

### Next up
- Week 2 Day 4 is complete
- Day 5: the four formal negative tests (no client cert, wrong-CA cert, expired cert, revoked cert) against the real `client.c`/`server.c` pair, each with verbatim captured rejection output and a one-sentence explanation of exactly where in the handshake the rejection happened

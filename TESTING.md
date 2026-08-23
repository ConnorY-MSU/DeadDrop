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

## Week 2, Day 5 — Negative testing

### Status: Complete. All four negative tests (no cert, wrong CA, expired, revoked) confirmed rejected, each for a distinct, correctly-identified reason. Happy path re-confirmed working after all four, per the Testing Standard's requirement to prove nothing regressed while building rejection logic.

### A real client-side blind spot found and fixed before testing could even be trusted

Running Test 2 first surfaced a genuine gap: the server's log clearly rejected the wrong-CA cert (`standard cert-chain verification failed`), but `client.c` printed `mTLS handshake succeeded.` anyway. Not a server bug — TLS 1.3 lets a client consider its own handshake "complete" the moment it sends its final flight, before the server's verdict on the client's certificate comes back, so a server-side rejection can arrive *after* `wolfSSL_connect()` already returned success. Since `client.c` (by Day 4's deliberate design) never read anything back, it had no way to ever notice this.

Fixed by adding one `wolfSSL_read()` call after the message send. This is safe specifically because `server.c` always closes the socket immediately after handling a connection — accepted or rejected — so the read never blocks waiting on a reply that isn't coming (the concern that shaped Day 4's original no-read-back decision only applies to waiting for an *echoed application message*, which is a different thing from noticing the connection closed). The resulting error string cleanly distinguishes the two cases without any extra logic needed — wolfSSL's own wording already does it:
- Benign close (happy path): `fatal I/O error in TLS layer`
- Genuine rejection: `received alert fatal error`

This is logged here rather than glossed over because it's a real example of why negative testing matters more than the happy path (per today's own walkthrough) — a passing happy-path test had been hiding a client-side observability gap that only a negative test could expose.

### Test 1 — No client certificate

| Field | Value |
|---|---|
| Method | wolfSSL's own example client, `-x` flag (disable client cert/key loading), pointed at this project's real CA, against the unmodified server |
| Expected result | Rejected during the handshake, before any application data exchanged |
| Actual result (server, verbatim) | `Raw TCP client connected.` then stderr: `Handshake failed: peer did not return a certificate` |
| Pass/fail | **PASS** |

**Why, precisely:** rejected before `my_verify_callback` ever ran at all — no "checking serial" log line appears, because there was no certificate to check. This is the most fundamental rejection point of the four: `WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT` makes presenting a certificate mandatory before verification logic gets a chance to run.

### Test 2 — Wrong-CA certificate

| Field | Value |
|---|---|
| Method | Generated a genuine second, throwaway CA (`throwaway-pki/`, outside the repo, disposable) and a client cert signed by it. Connected with this project's real `client.c`, pointing `-c`/`-k` at the throwaway-CA cert but keeping `-A` on this project's real CA (so the client still correctly trusts the server) |
| Expected result | Server rejects — trusts only its own configured CA, not any certificate that happens to be validly signed by *something* |
| Actual result (server, verbatim) | `Verify callback: standard cert-chain verification failed.` / `Handshake failed: certificate verify failed` |
| Actual result (client, verbatim, after the read-back fix) | `mTLS handshake succeeded.` / `Sent: hello from client.c` / `Post-send read: received alert fatal error` |
| Pass/fail | **PASS** |

**Why, precisely:** rejected by wolfSSL's own built-in chain verification (`preverify_ok` was 0) before `my_verify_callback`'s own revocation-check logic ever ran — the certificate was well-formed and internally consistent, just signed by a CA this server was never configured to trust. Independently confirmed with plain `openssl verify -CAfile <real ca>`, which fails with `unable to get local issuer certificate` on the same cert.

### Test 3 — Expired certificate

| Field | Value |
|---|---|
| Method | Generated a client cert signed by this project's **real** CA (isolating the date check from the CA-trust question already covered by Test 2), backdated via `openssl x509 -req -not_before 20200101000000Z -not_after 20200201000000Z`. Connected with the real `client.c` |
| Expected result | Server rejects specifically for expiration, not a generic chain failure |
| Actual result (server, verbatim) | `Verify callback: standard cert-chain verification failed.` / `Handshake failed: ASN date error, current date is after expiration` |
| Actual result (client, verbatim) | Same shape as Test 2: `mTLS handshake succeeded.` / `Sent: hello from client.c` / `Post-send read: received alert fatal error` |
| Pass/fail | **PASS** |

**Why, precisely:** same fail-fast point as Test 2 (`preverify_ok` 0, before the revocation callback logic runs) but with a distinctly different, specific reason string — `ASN date error, current date is after expiration` vs. Test 2's generic `certificate verify failed` — proving date-validity is a real, independently-enforced part of wolfSSL's chain verification, not something this project's code has to implement itself.

### Test 4 — Revoked certificate

| Field | Value |
|---|---|
| Method | This project's real, correctly-signed, non-expired client cert (`client_cert.pem`) — its actual serial (`68A7E95F14813C60A047706956F72BA0CCCC83F9`) added to `revoked_serials.txt`, server restarted (the list only loads at startup) |
| Expected result | Rejected despite a completely valid chain — proves the Day 2 revocation module is load-bearing, not just present in the code |
| Actual result (server, verbatim) | `Verify callback: checking serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 against revocation list.` then stderr: `Verify callback: serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 is REVOKED - rejecting.` / `Handshake failed: verify problem on certificate` |
| Actual result (client, verbatim) | Same shape as Tests 2/3: `Post-send read: received alert fatal error` |
| Pass/fail | **PASS** |

**Why, precisely:** the only one of the four tests where `preverify_ok` was actually 1 and `my_verify_callback`'s own logic (not wolfSSL's built-in chain check) is what caught and rejected the connection — visible directly in the log, since "checking serial..." only ever appears once the chain itself has already passed. This is the concrete proof the revocation check is wired into the live handshake path, not dead code.

### Part C — Confirm nothing broke

Re-ran the exact Day 4 happy-path command one more time after all four negative tests, revoked-serials list cleared and server restarted:
```
Connected to server.
mTLS handshake succeeded.
Sent: hello from client.c
Post-send read: fatal I/O error in TLS layer
```
Server: `mTLS handshake succeeded.` / `Client message: hello from client.c`. `fatal I/O error in TLS layer` (not `received alert fatal error`) confirms this is genuinely the benign case — building four rejection paths didn't make the verify callback or revocation check overly aggressive against the legitimate case.

### Bugs hit and how they were resolved
1. The client-side blind-spot finding detailed above — `client.c` couldn't previously detect a post-handshake server rejection at all; fixed with a post-send `wolfSSL_read()`, verified safe against the happy path first.
2. `openssl req -subj "/C=US/..."` inside Git Bash: the leading `/C=US/...` gets auto-mangled into a Windows path by MSYS's path-conversion heuristics (`/C=US/...` looks enough like a drive-letter path to trigger it). Fixed with `MSYS_NO_PATHCONV=1` for just that command — and immediately unset afterward, since the same override breaks genuine `/c/Users/...` path arguments in other commands in the same session.
3. Every actual test *result* was correct on the first real attempt once the client's read-back gap was fixed — no further surprises across Tests 3 and 4.

### Next up
- Week 2 Day 5 is complete — all five days of Week 2 are done
- Still open, the user's own responsibility per the project's standing convention: Week 1 Self-Check Questions, Week 2 Day 1/3's Learning items, and [[Week 2 Self-Check Questions]]
- Confirm [[00-Start Here/Four-Week Roadmap|Four-Week Roadmap]]'s "End of Week 2" checklist, then Week 3 (protocol design, WireGuard/Tailscale, memory safety)

## Full-project audit — 2026-08-20

A deliberate, full read-through of the existing codebase and curriculum, looking for gaps and technical problems rather than building new features. Full findings and fixes below; status: all code-level findings fixed and re-verified against the existing test suite (nothing regressed), curriculum-level finding fixed by restructuring the affected days.

### Finding 1 (major): `server.c`/`client.c` were Windows-only

Discovered while implementing the timeout fix below (Finding 2) — both files used `winsock2.h`/`ws2tcpip.h`, `WSAStartup`/`WSACleanup`, `SOCKET`, `closesocket`, `WSAGetLastError`, none of which exist on Linux. As written, neither file would have compiled at all on the Raspberry Pi — Week 4's entire deployment target.

**Fix:** added a portability shim (`#ifdef _WIN32` / `#else`) in both files covering: headers, socket type (`socket_t`), invalid/error sentinels, close call, and error-code retrieval. `WSAStartup`/`WSACleanup` are now compiled only under `_WIN32`. The POSIX branch is written to standard POSIX socket API conventions but has not been compiled or run on Linux yet — that verification has to happen for real once Week 4 Day 1 builds natively on the Pi, same "verify against the real target, don't assume" discipline as every wolfSSL flag this project has hit so far.

**Verified:** recompiled clean (zero warnings) on the `_WIN32` path, reran the full existing test suite (`test_revocation.c`, 8/8) and a live client/server mTLS handshake — identical results to before the change.

### Finding 2 (major): no connection timeout; server is single-threaded and sequential

`server.c`'s `accept()` loop fully handles one connection (accept → handshake → read → close) before accepting the next, with no timeout anywhere. A stalled or malicious peer that opens a connection and never completes the handshake blocks the server from accepting *anyone* else — including the legitimate peer's own Week 3 Day 2 reconnect attempt.

**Fix:** added `set_socket_timeout()`, applied to each accepted client socket before the handshake begins — `SO_RCVTIMEO`/`SO_SNDTIMEO`, 30 seconds (generous for a real handshake on a slow/mobile network, short enough that one stalled connection doesn't lock everyone else out for long). Implemented per-platform inside the same portability shim (Windows: `DWORD` milliseconds; POSIX: `struct timeval`).

**Verified:** same recompile/retest as Finding 1 — no behavior change on the happy path, confirmed by the same live handshake test.

### Finding 3: `revocation.c`'s buffer was one byte too small for what `server.c` could hand it

`server.c`'s `SERIAL_BUF_SIZE` (32 raw bytes) means its `serial_hex` string can be up to 64 hex characters. `revocation.c`'s old `MAX_SERIAL_LEN` was 64, but `strncpy(..., MAX_SERIAL_LEN - 1)` only copied 63 usable characters, silently truncating a maximum-length serial. Two 64-character serials differing only in the last character would have collided after truncation. Not currently exploitable (real X.509 serials are ≤40 hex chars per RFC 5280, and the CA is fully trusted/controlled), but a genuine sizing mismatch between two files that should agree.

**Fix:** `MAX_SERIAL_LEN` raised to 80, with a comment explaining the derivation (32-byte `SERIAL_BUF_SIZE` → 64 hex chars → margin, not a tight fit) so the next person to touch either constant sees the dependency.

**Verified:** `test_revocation.c`, 8/8 passing, unchanged.

### Finding 4: `revocation_load()` had no defense against an over-length line

`fgets()` would silently split a line longer than the read buffer across two calls, loading the leftover tail as its own bogus, unrelated "revoked serial" entry — low risk given the controlled file format (real entries are ~40 chars, well under the buffer), but a real robustness gap.

**Fix:** detect truncation (line fills the buffer with no trailing `\n`), discard the remainder of that line via `fgetc()`, warn, and skip the entry entirely rather than partially loading it.

**Verified:** `test_revocation.c`, 8/8 passing, unchanged (none of the existing test fixtures exercise this path, since none of them use an over-length line — the fix is defensive, not a behavior change for any currently-tested input).

### Finding 5 (documented, not changed): verify callback assumes a single-level cert chain

`wolfSSL_X509_STORE_CTX_get_current_cert()` returns whichever certificate is currently being verified, which is only guaranteed to be the leaf when the chain has exactly one certificate. This project's PKI is single-level by design (CA signs each device's leaf cert directly, no intermediates), so this is correct today — already empirically proven by every passing revocation test, which specifically checks the leaf's own serial. Documented as an explicit assumption directly in `server.c` (comment above `my_verify_callback`) so it's not silently wrong if an intermediate CA is ever introduced later.

### Finding 6 (documented, not changed): `server.c`'s cleanup code is unreachable

The `for (;;)` accept loop never breaks, so the cleanup code after it (`CLOSE_SOCKET`, `wolfSSL_CTX_free`, `revocation_free`, etc.) never runs under normal operation. Neither `server.c` nor `client.c` installs a signal handler, so `systemctl stop` (which sends `SIGTERM`) would terminate the process exactly as abruptly as `kill -9` does today — the graceful-shutdown path Week 4 Day 5's crash test doesn't actually exercise, since that test uses `kill -9` specifically. Left unimplemented rather than guessed at: a correct fix needs platform-specific signal handling (POSIX `signal()`/`sigaction()` vs. Windows `SetConsoleCtrlHandler()`) and a way to actually interrupt a blocking `accept()` call, neither of which can be verified from this dev environment. Documented directly in `server.c` with a comment explaining the gap and pointing at Week 4 as the place to actually fix it, once this is building and running natively on the Pi.

### Finding 7 (minor): `client.c`'s `-p` argument wasn't validated

`atoi()` on a non-numeric or out-of-range value silently produced `0` or garbage, rather than a clear error. **Fixed:** added a range check (`1`–`65535`) with a specific error message, right after the existing required-argument check.

### Finding 8 (curriculum-level, major): the overlay filesystem conflicts with several things that need to persist

Week 4 Day 1's overlay-filesystem decision was made before several later features existed that genuinely need to survive a reboot: **Tailscale's own node authentication state** (without it, the device re-prompts for a fresh login every boot — a direct violation of the "zero manual steps" milestone), **the Days 2-3 PIN lock's salted hash**, **NetworkManager's saved WiFi profiles** (the mobility work), and **any certificate deployed via the Day 6 rotation drill** (a write happening after the overlay is already active). None of this was connected anywhere in the curriculum.

**Fix:** restructured the curriculum rather than just adding a warning — the overlay filesystem is no longer enabled on Day 1 at all. It's deferred to Day 5 (new Part A.0 in that day's walkthrough), once the complete persistence list is actually known, with explicit "note for Day 5" markers left at each point earlier in the week where a new persistence requirement gets created (Tailscale auth on Day 1, PIN hash and WiFi profiles on Days 2-3). Day 5 now includes setting up persistent storage for all three *before* enabling the overlay, plus a reboot-and-verify step. The Day 6 rotation drill now explicitly calls out that its certificate deployment is itself a write happening after the overlay is active, and requires a reboot-and-recheck to actually prove the deployment survives. Updated: [[Embedded Linux Deployment Concepts]], [[Week 4 Build Log]] (Days 1, 2-3, 5, 6), [[Week 4 Day 1 Walkthrough]], [[Week 4 Day 5 Walkthrough]], [[Week 4 Day 6 Walkthrough]], [[Week 4 Self-Check Questions]].

### Not yet done
- `docs/PROTOCOL.md` existed on disk but wasn't committed to git before this audit — fixed as part of this session's commits.
- `revocation.c` has no thread-safety (no locking on its global state) — not currently a problem given single-threaded, load-once-at-startup usage, but worth revisiting if Week 4's ncurses UI ends up using a threaded design.

### Re-scan — verifying the fixes themselves, not just re-reading the code

A second pass specifically checking whether the audit's own fixes actually hold up, rather than trusting the first pass's reasoning.

**Empirically proved the connection timeout (Finding 2) actually works, not just "didn't break the happy path."** Opened a raw TCP connection via bash's `/dev/tcp` that connects but never sends anything (no TLS handshake, simulating a stalled/malicious peer) and held it open past the 30-second timeout, while the server was live:
```
Raw TCP client connected.
[... 30s elapses ...]
Handshake failed: non-blocking socket wants data to be read
```
Then immediately ran a real client against the same server — it succeeded cleanly, confirming the server genuinely recovered and served the next connection rather than staying stuck:
```
Raw TCP client connected.       <- the stalled one
Raw TCP client connected.       <- the real one, right after
Verify callback: checking serial ... not revoked, proceeding.
mTLS handshake succeeded.
Client message: hello from client.c
```
**One thing worth flagging, not a bug:** the error string wolfSSL surfaces for this timeout (`non-blocking socket wants data to be read`, i.e. its internal `WANT_READ` condition) is the same shape of message normally meaning "retry me," not "this timed out and should be treated as fatal." Our code doesn't retry on it — correctly, in this context — but a future reader debugging server logs should know this specific message, in this specific spot, means the 30s timeout fired, not that something is misconfigured for non-blocking I/O.

**Found one more, very minor, edge case in the truncation fix (Finding 4) while re-checking it by hand:** if the revoked-serials file's very last line is exactly 79 characters (one short of the 80-byte buffer) with no trailing newline (because the file simply ends there), the current logic would misidentify it as truncated and skip it, even though it's actually complete. Real revoked serials are ~40 hex characters, so this would need a file crafted to land exactly on that specific boundary to ever trigger — not fixed, given how narrow it is, but noted honestly rather than claiming the truncation fix is airtight in every conceivable case.

## Week 3, Day 2 — Protocol implementation review — 2026-08-20

`src/message.c`/`src/hmac.c` (`sl_serialize_message`/`sl_try_parse_message`/`sl_session_init`, plus a from-scratch `hmac_sha256` built on Week 1's own `sha256_context`) were written against `docs/PROTOCOL.md`'s exact spec. Reviewed line-by-line against the spec (byte offsets, HMAC coverage `[0, 12+N)`, key-derivation label, `seq_num` strictly-increasing rule, 65536-byte cap, failure-handling order) before ever compiling, then verified for real: built, linked, and run as a live client/server exchange over loopback, not just read for logical correctness.

### Finding 1 (portability): `include/HMAC.H` / `src/HMAC.c` vs. `#include "hmac.h"`

Both `message.c` and (its own) `HMAC.c` `#include "hmac.h"` (lowercase), but the actual header was `HMAC.H` (uppercase, `.H` extension). Compiles silently on Windows (NTFS is case-insensitive) but would fail to find the header at all on the Week 4 deployment target (Raspberry Pi OS, ext4 — case-sensitive) — the same category of Windows-only assumption as the earlier full-project audit's Finding 1. Also inconsistent with every other header in the project (`sha256.h`, `aes128.h`, `revocation.h`, `message.h`, `debug.h` are all lowercase).

**Fix:** renamed both files to lowercase (`include/hmac.h`, `src/hmac.c`).

### Finding 2 (blocker): `wolfSSL_export_keying_material()` wasn't actually compiled into the installed wolfSSL build

`docs/PROTOCOL.md`'s own "Implementation note for Day 2" explicitly flagged this as a risk to check before implementing. Confirmed the gap concretely rather than assuming: `nm libwolfssl.a | grep export_keying_material` returned nothing, and compiling `message.c` failed with `implicit declaration of function 'wolfSSL_export_keying_material'`. The function exists in `ssl.h` but is gated behind `HAVE_KEYING_MATERIAL`, which the project's wolfSSL build (last configured Week 2 Day 3) never enabled.

**Fix:** rebuilt wolfSSL with `--enable-keying-material` added to the configure line. Full details — including two more real problems hit along the way (a `-Werror`-from-git-checkout autoconf/GCC interaction, and a second missing feature flag needed for `make install` to succeed cleanly) and the exact final configure/build/link commands — are in `docs/BUILD.md`'s new "Rebuild — Week 3, Day 2" section rather than duplicated here.

**Verified:** `grep HAVE_KEYING_MATERIAL wolfssl/options.h` and `nm libwolfssl.a | grep export_keying_material` both confirm the symbol is genuinely compiled in (not just declared) in the installed library.

### Finding 3 (runtime bug, found only by actually running it): `wolfSSL_export_keying_material()` requires `wolfSSL_KeepArrays(ssl)` before the handshake

Even after Finding 2's rebuild, a live client/server run failed at `sl_session_init()` on both sides — `wolfSSL_export_keying_material()` linked and ran, but returned `WOLFSSL_FAILURE` with no wolfSSL error attached (`wolfSSL_get_error` reported `0`/`"ok"`), which gave no clue from the symptom alone. Traced by reading `wolfSSL_export_keying_material`'s own implementation in wolfSSL's `src/ssl.c` directly: it requires `ssl->options.saveArrays` to be set, which only happens if `wolfSSL_KeepArrays(ssl)` is called *before* the handshake — wolfSSL frees its internal handshake arrays once the handshake completes, by default, to save memory.

**Fix:** added `wolfSSL_KeepArrays(ssl)` in both `client.c` (before `wolfSSL_connect()`) and `server.c` (before `wolfSSL_accept()`), and a matching `wolfSSL_FreeArrays(ssl)` inside `sl_session_init()` itself right after a successful export, so the retained memory isn't held for the rest of a potentially long-lived interactive session.

**Verified:** re-ran the live exchange; both sides derived a key and a real message round-trip succeeded (see below).

**First successful live exchange (before Finding 4 below was found), verbatim:**
```
Client:
Connected to server.
mTLS handshake succeeded.
Connected. Type a message and press Enter (or 'quit' to exit).
> Server: ack: hello from client.c
> Server: ack: ping test coming next... wait no lets just send another message
>
```
```
Server:
Raw TCP client connected.
Verify callback: ... not revoked, proceeding.
mTLS handshake succeeded.
Received TEXT_MESSAGE (seq=0, 19 bytes)
Client message: hello from client.c
Received TEXT_MESSAGE (seq=1, 63 bytes)
Client message: ping test coming next... wait no lets just send another message
```
Correct `seq_num` tracking (0, then 1), correct body lengths, correct HMAC verification (a bad tag would have been silently rejected per the failure table, not echoed back), correct framing of two independently-typed messages.

### Finding 4 (runtime bug, found only by actually running it): `DISCONNECT` sent by the client never arrived at the server

Continuing the same live test past `quit`: the client's `send_message(..., SL_MSG_DISCONNECT, ...)` returned success (no error printed), but the server sat blocked in `wolfSSL_read()` indefinitely — `Received DISCONNECT` never appeared in its log, confirmed by checking back repeatedly over several seconds and confirming the server process was still alive and not merely slow.

Root cause: neither `client.c` nor `server.c` called `wolfSSL_shutdown()` before `wolfSSL_free()` — both tore down the TLS session abruptly. On Windows/Winsock, closing a socket that still has unread bytes sitting in its receive buffer (e.g. a post-handshake TLS 1.3 session ticket the client never explicitly reads, since the client only calls `wolfSSL_read()` when it's expecting a reply) can make the OS send a hard RST instead of a graceful FIN — which can abort delivery of whatever was just sent immediately beforehand, in this case the `DISCONNECT` message, before the peer's application layer ever sees it.

**Fix:** added `wolfSSL_shutdown(ssl)` before `wolfSSL_free(ssl)` on both the client's post-session path and the server's post-`handle_connection()` path — a single best-effort call (sends this side's `close_notify`, doesn't block waiting for the peer's own `close_notify` in return, so a peer that's already gone doesn't hang the caller).

**Update — Smart App Control blocker resolved (user disabled it) and Finding 4 re-tested. The `wolfSSL_shutdown()` fix alone did *not* actually fix delivery — the real cause was something else entirely, found by instrumenting both sides directly rather than continuing to guess:**

Added temporary debug output around the client's `DISCONNECT` send and the server's `wolfSSL_read()` call. Result: the server's `wolfSSL_read()` *did* return `n=44` (exactly a `DISCONNECT` message's size) — the bytes were arriving and being read all along. What was actually happening: `handle_connection()`'s `printf("Received %s (seq=%u, %u bytes)\n", ...)` had no `fflush()` after it (unlike the `TEXT_MESSAGE` branch three lines below it, which does), and neither did the `PING`/`PONG`/`DISCONNECT`-specific `printf`s further down. Because stdout is fully block-buffered when redirected to a file/pipe (not a TTY), those lines were sitting unflushed in the buffer while the server correctly finished the connection and went back to blocking in `accept()` for the next client — which, observed from outside, looks identical to a genuine hang. **The `wolfSSL_shutdown()`/`wolfSSL_KeepArrays()` fixes above were real and worth keeping (`KeepArrays` in particular is a genuine hard requirement, not optional), but the specific symptom that originally looked like a missing-`DISCONNECT` delivery bug was actually this logging gap the whole time.**

**Fix:** added `fflush(stdout)` after the unconditional `"Received %s..."` line and after the `PING`/`PONG`/`DISCONNECT`-specific lines, so server-side log output is reliably visible in real time rather than only on process exit.

**Verified — full live re-test, verbatim server output:**
```
Raw TCP client connected.
Verify callback: checking serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 against revocation list.
Verify callback: serial 68A7E95F14813C60A047706956F72BA0CCCC83F9 not revoked, proceeding.
mTLS handshake succeeded.
Received TEXT_MESSAGE (seq=0, 19 bytes)
Client message: hello from client.c
Received TEXT_MESSAGE (seq=1, 19 bytes)
Client message: second message here
Received DISCONNECT (seq=2, 0 bytes)
Peer sent DISCONNECT - closing cleanly.
```
Server process confirmed still alive and correctly back in its accept loop afterward (checked via `tasklist`, not assumed) — proved by immediately running a **second**, independent client connection against the same still-running server, which worked cleanly with `seq_num` correctly reset to `0` for the new session (per `PROTOCOL.md`'s per-session-reset design) and its own clean `DISCONNECT`. **Finding 4 is now genuinely verified**, not just fixed-and-hoped.

### Finding 5: `server.c`'s echo can exceed `SL_MAX_BODY_LEN` — fixed (truncate) and verified

Decision (user's call, per this project's build-your-own-protocol-logic discipline): truncate the echoed body so `"ack: " + body` never exceeds `SL_MAX_BODY_LEN`, rather than dropping the prefix or failing the reply outright — a message this close to the cap is already an edge case on the sender's side, so losing a few trailing bytes of the *echo* is an acceptable tradeoff against dropping the whole reply (and connection) over it.

**Fix:** `reply_len` explicitly capped to `SL_MAX_BODY_LEN` in `handle_connection()`'s `TEXT_MESSAGE` branch, after the existing buffer-size check.

**Verified with a real boundary case, not just a code read:** sent a 65533-byte message (3 bytes under the cap) — small enough to be legal, large enough that `"ack: "` (5 bytes) pushes the natural echo to 65538, two bytes over. Server log confirmed the full message received intact (`Received TEXT_MESSAGE (seq=0, 65533 bytes)`, full 65533-byte body logged correctly), and the client's received reply measured out to exactly `SL_MAX_BODY_LEN` (65536) bytes — `"ack: "` plus 65531 of the original 65533 `A`s, the expected two-byte truncation, no more and no less. No crash, no dropped connection; the session's subsequent `DISCONNECT` was received and processed cleanly afterward, same as every other test.

### Full regression check after all of the above
`test_revocation.exe` (8/8), `test_aes128.exe`, `test_sha256.exe` — all still passing clean, no regressions from any of today's changes.

### Finding 6 (closed the two remaining gaps flagged above): reconnect-with-backoff live-tested, and `message.c`/`hmac.c` unit tests added

**Reconnect/backoff, live-tested for real** (previously implemented and code-reviewed only): started a real client/server session, sent a message, confirmed the ack, then killed the server process outright to simulate a real dropped connection while the client stayed running. Verbatim client output:
```
> Server: ack: message before drop
> wolfSSL_write: fatal I/O error in TLS layer
Disconnected - retrying in 1 second(s)...
connect() failed: 10061
Disconnected - retrying in 2 second(s)...
connect() failed: 10061
Disconnected - retrying in 4 second(s)...
Connected to server.
mTLS handshake succeeded.
Connected. Type a message and press Enter (or 'quit' to exit).
> Server: ack: message after reconnect
```
The drop was detected almost immediately (`wolfSSL_write` failed outright — Windows sends an RST when the peer process is killed, so this didn't need to fall back on the 30-second `SO_RCVTIMEO`), backoff correctly doubled on each failed retry (1s → 2s → 4s) while the server was down, and the very next attempt after the server came back succeeded. Server-side log for the post-reconnect session: `Received TEXT_MESSAGE (seq=0, 23 bytes)` — confirms `seq_num` correctly reset to 0 for the new session, exactly per `PROTOCOL.md`'s per-session design, not carried over from the dropped one.

(Test-harness note, not a project bug: an initial attempt to script this used a named FIFO opened via `exec 3<>fifo` to keep the client's stdin alive across multiple sends — that produced an immediate spurious `DISCONNECT (seq=0)` from the client reading EOF on its very first `fgets()`, a Git-Bash/MSYS FIFO-emulation quirk, not a client.c bug. Switched to `tail -f` on a growing file as the client's stdin instead, which worked reliably.)

**`message.c`/`hmac.c` unit tests added**: `tests/test_hmac.c` (RFC 4231 HMAC-SHA-256 test vectors — Test Cases 1, 2, 3, and 6; Case 6 specifically exercises the key-longer-than-block-size hashing branch none of the others touch) and `tests/test_message.c` (round-trip correctness against `PROTOCOL.md`'s own worked byte example, HMAC tag tamper detection, body tamper detection, exact-replay rejection, strictly-increasing `seq_num` acceptance, oversized `body_length` rejected with no safe resync point, partial/incomplete-message detection at two different boundaries, unrecognized-version and unrecognized-msg_type rejection each isolated with a freshly-recomputed valid HMAC so the rejection is provably about that specific field and not a coincidental tag mismatch, two independent messages parsed correctly out of one combined buffer, and `DISCONNECT`'s zero-length-body edge case) — 29 assertions total, all passing, isolated from wolfSSL/TLS entirely by populating `sl_session_state` with a fixed test key directly rather than going through `sl_session_init()`.

Since the RFC 4231 vectors were transcribed from memory rather than a locally verifiable source (unlike Week 1's downloaded NIST PDF for SHA-256), independently cross-checked `hmac_sha256()` against wolfSSL's own mature `wc_Hmac` API on the same four inputs before trusting the result either way — all four agreed exactly, real independent confirmation rather than an implementation and its hand-typed expected value coincidentally sharing the same transcription error.

```
[PASS] RFC 4231 Test Case 1 (20-byte key)
[PASS] RFC 4231 Test Case 2 (short key, "Jefe")
[PASS] RFC 4231 Test Case 3 (0xdd-filled data)
[PASS] RFC 4231 Test Case 6 (key > block size)

ALL VECTORS PASSED
```
```
[PASS] serialize returns correct total size (12+5+32) (got 49, expected 49)
... (29 total)
[PASS] DISCONNECT body_len is 0 (got 0, expected 0)

ALL VECTORS PASSED
```

Full five-binary regression after adding both: `test_revocation` (8/8), `test_sha256`, `test_aes128`, `test_hmac` (4/4), `test_message` (29/29) — all clean.

### Not yet done
- POSIX branch of the portability shim (`server.c`/`client.c`, from the earlier full-project audit) is still unverified on real Linux — unchanged by today's work, still deferred to Week 4 Day 1 by design.

## Week 3, Day 3 (partial) — Tailscale prep, no second device yet — 2026-08-21

Pi hardware exists but isn't running an OS yet (Week 4 Day 1), so there's no real second machine to test cross-network reachability against today. Did the parts of Day 3 that don't depend on one existing; the actual cross-network exchange and Wireshark capture are deferred (see `docs/PROTOCOL.md`'s new "Network transport and addressing" section and `docs/tailscale-acl.json`).

**Tailscale installed on this dev machine:** `winget install tailscale.tailscale` (v1.102.2), confirmed via `tailscale.exe version`. Not yet authenticated (`tailscale status` → `Logged out`) — `tailscale up`'s browser-based login is inherently interactive and out of scope for automated setup; left for the user to complete.

**`client.c`: `inet_pton()` replaced with `getaddrinfo()`-based resolution.** `inet_pton()` only parses numeric IP address text — it does zero name resolution, so it would have silently rejected a Tailscale MagicDNS hostname outright. This needed to change regardless of which addressing option (hardcoded IP vs. MagicDNS) eventually gets chosen, so made the change now rather than gating it on that decision. `getaddrinfo()` handles both a raw IP and a real hostname through the same code path.

**Verified with both kinds of input, not just one:**
```
=== test with raw IP 127.0.0.1 ===
Connected to server.
mTLS handshake succeeded.
Connected. Type a message and press Enter (or 'quit' to exit).
> Server: ack: ip test
=== test with hostname 'localhost' ===
Connected to server.
mTLS handshake succeeded.
Connected. Type a message and press Enter (or 'quit' to exit).
> Server: ack: hostname test
```
Server log confirms both were genuinely received and processed (`Received TEXT_MESSAGE ... Client message: ip test` / `... Client message: hostname test`), not just that the client printed something. `localhost` specifically is a real hostname resolution `inet_pton()` could never have performed — this is the concrete proof the swap actually does what it's for, not just that it compiles.

Full five-binary regression suite re-run after the change: `test_revocation`, `test_sha256`, `test_aes128`, `test_hmac`, `test_message` — all still clean.

**Tailscale ACL policy drafted** (`docs/tailscale-acl.json`): tag-based (`tag:securelink-client`/`tag:securelink-server`), restricts the two devices to reaching only each other on port 4433, default-deny for everything else once any custom rule exists. Written and ready to paste into the admin console now; applying `tag:securelink-server` to a Pi is deferred until one is actually running Tailscale.

## Update — same day, authenticated and tagged for real

User completed `tailscale up`'s interactive browser login and pasted `docs/tailscale-acl.json` into the admin console. Applied `tag:securelink-client` to this dev machine via `tailscale up --advertise-tags=tag:securelink-client` — **one real hiccup along the way, not glossed over**: the first attempt at this, run *before* the ACL policy had been pasted into the console, pushed the client into `BackendState: NeedsLogin` (requesting a tag that doesn't yet exist in `tagOwners` apparently requires a fresh interactive approval that a headless CLI call can't complete). Recovered with `tailscale up --reset --accept-risk=all` before the ACL was in place, confirmed back to a healthy `Running` state via `tailscale status`, then retried the tag *after* the ACL was actually pasted — this time it applied cleanly with no re-auth needed, confirmed via `tailscale up`'s own output (no `NeedsLogin`/`AuthURL` this time) and independently via:
```
tailscale whois 100.107.213.69
  ...
  Tags:          tag:securelink-client
```
Also visible as a side effect: `tailscale status` now shows this device by its tagged hostname (`lapbottom.taild5c2a6.ts.net`) rather than the personal login email it showed before tagging — consistent with a tagged device being identified by the tag/service rather than the user who happened to authenticate it, exactly the intended behavior for this ACL model.

### Not yet done (Day 3)
- A second device authenticated and tagged `tag:securelink-server`; confirming the ACL actually restricts traffic as intended (not just that this one device's tag looks right) needs that second device to exist.
- Re-running the Day 2 interactive exchange over the real Tailscale path.
- The `tshark`/Wireshark capture on the Tailscale interface.
- The addressing decision itself (hardcoded IP vs. MagicDNS) — deferred until there's a real second device to decide it against.

## Week 3, Day 4 — Benchmarking — 2026-08-21

`src/benchmark.c` written (by the user): `run_handshake_benchmark()` (10,000 fresh TCP-connect-plus-full-mTLS-handshake iterations, timed from just before `wolfSSL_new()` to just after `wolfSSL_connect()` returns — deliberately includes SSL object setup, not just the wire round-trip, since that's genuinely part of this project's real per-connection cost) and `run_throughput_benchmark()` (one persistent connection, many `TEXT_MESSAGE` round-trips at a fixed payload size, timed send-to-ack). Run against an already-running `server.exe`, same cert/key/CA CLI args as `client.c`.

### Two real bugs found by actually running it, not by reading it

**1. `run_throughput_benchmark()` was missing `wolfSSL_KeepArrays(ssl)`** before its own `wolfSSL_connect()` call. `run_handshake_benchmark()` correctly had it; the throughput path does its own separate connect/handshake and didn't. Result: `sl_session_init()` failed on every throughput iteration with the exact Day 2 `wolfSSL_export_keying_material failed (rc=0, err=0: ok)` symptom, and both throughput benchmarks silently produced zero samples (the failure path `goto cleanup`s before `print_stats()` ever runs, so the final report didn't even show a "no samples collected" line for them — worth knowing if this class of failure ever recurs). **Fix:** added the missing call, with a comment cross-referencing why.

**2. `open_tcp_connection()` still used `inet_pton()`**, unaware that `client.c` had already moved to `getaddrinfo()`-based resolution in the Day 3 prep commit (`ba6ab0d`) specifically because `inet_pton()` can't resolve a Tailscale MagicDNS hostname at all. Confirmed failing exactly as expected: `inet_pton failed for host 'localhost'`, where `client.exe` already succeeded on the same input. **Fix:** brought `open_tcp_connection()` in line with `client.c`'s exact `getaddrinfo()` pattern (including the `<netdb.h>` include benchmark.c's own copy of the portability shim was missing).

**A third finding — now fixed too:** `run_handshake_benchmark()`'s loop recorded `samples[i]` from `t0`/`t1` before checking whether `wolfSSL_connect()` actually succeeded, so a failed handshake attempt's timing would have been silently mixed into the same stats as successful ones, with no visible failure count. Didn't manifest in any run today (zero handshake failures across 30,000+ total iterations across four full runs), but real gap in the methodology regardless. **Fix:** separated the loop counter (`i`, attempts) from a new `valid` counter (successful handshakes actually recorded into `samples[]`); a failed handshake now increments a `failures` counter instead of writing a sample, and a nonzero `failures` count is explicitly reported (`"N of M attempted handshakes failed and were excluded..."`) rather than silently absorbed. **Verified**: re-ran the full benchmark after the fix — `n=10000` (all handshakes counted, `valid` correctly reached the full iteration count with zero exclusions) and no failure-count line printed, confirming the fix doesn't spuriously trigger on a normal clean run:
```
Handshake (connect+TLS)      n=10000  min=  12.2912 ms  median=  13.9725 ms  mean=  13.9266 ms  max=  29.5377 ms
Throughput (small payload)   n=2000   min=   0.0526 ms  median=   0.0574 ms  mean=   0.0652 ms  max=   0.4562 ms
Throughput (large payload)   n=500    min=   0.6113 ms  median=   0.9560 ms  mean=   0.9590 ms  max=   2.3239 ms
```
Consistent with the prior two runs (see above). Full regression suite re-run once more after this fix too — still clean.

### Verified — both fixes confirmed by actually re-running it, not just recompiling

Full 10,000-iteration handshake run plus both throughput benchmarks, twice independently (once addressed by raw IP, once by hostname — the second run doubles as proof the `getaddrinfo()` fix genuinely works end to end, not just that it compiles):

**By IP (`-h 127.0.0.1`):**
```
Handshake (connect+TLS)      n=10000  min=  12.7036 ms  median=  14.2351 ms  mean=  14.4251 ms  max=  62.1724 ms
Throughput (small payload)   n=2000   min=   0.0580 ms  median=   0.0614 ms  mean=   0.0721 ms  max=   0.4948 ms
Throughput (large payload)   n=500    min=   0.6215 ms  median=   0.9637 ms  mean=   0.9541 ms  max=   1.8660 ms
```

**By hostname (`-h localhost`) — proves the getaddrinfo() fix, wouldn't have run at all before it:**
```
Handshake (connect+TLS)      n=10000  min=  12.3684 ms  median=  14.0150 ms  mean=  14.1088 ms  max=  37.6308 ms
Throughput (small payload)   n=2000   min=   0.0525 ms  median=   0.0569 ms  mean=   0.0668 ms  max=   0.3373 ms
Throughput (large payload)   n=500    min=   0.5875 ms  median=   0.9374 ms  mean=   0.9398 ms  max=   2.6111 ms
```

Consistent across both runs, as expected (dev-machine numbers, **not final performance** — the program's own banner says so explicitly, and this needs re-running on the Pi once it's up in Week 4). Handshake latency (~12-14ms typical) is roughly 200x a single small-message round-trip (~0.06ms) — worth carrying into the write-up: a cost paid once per session is a very different thing from the same cost paid on every message.

Note the max/median gap, especially on handshake (62ms max vs. ~14ms median in one run — over 4x): real tail latency, exactly the kind of thing an average alone would have hidden, per the walkthrough's own point about why min/median/max matters over a single number.

Full five-binary regression suite re-run after both fixes: `test_revocation`, `test_sha256`, `test_aes128`, `test_hmac`, `test_message` — all still clean, unaffected (as expected — `benchmark.c` is a new standalone file, doesn't touch any of the tested modules).

### Not yet done (Day 4)
- Re-running on real Pi hardware once it's up (Week 4) — today's numbers are dev-machine only, clearly labeled as such both in the program's own banner and here.
- The required README write-up paragraph (numbers-grounded judgment on whether this is fast enough for the stated use case) — not written yet.
- Confirming this was built as a plain, non-sanitized release build (it was — same `gcc -Wall -Wextra -g` line as `client.c`/`server.c`, no `-fsanitize=` flags — worth restating explicitly here since Day 5's sanitizer build is coming next and it would be easy to conflate the two).

## Week 3, Day 5 — Full hardening pass — 2026-08-21

Every binary rebuilt and re-run under AddressSanitizer + UndefinedBehaviorSanitizer, a full fuzz harness written and run against the protocol parser, a secrets audit, and a full regression re-check — the same discipline as Week 1 Day 5's hardening pass, applied to everything Weeks 2 and 3 added since.

### Standard for "clean" (decided up front, per the walkthrough's own instruction, before running anything)

**Zero tolerance** for any ASan report, any UBSan report, and any crash/hang, on any binary, under any test in this section — no exceptions, no "acceptable" category. (Valgrind's "still reachable vs. definitely lost" distinction doesn't apply here at all, since Valgrind isn't available and wasn't used — see below — but the equivalent standard under ASan/UBSan is the same as it's been since Week 1: the sanitizers either report a real problem or they don't, there's no analogous "acceptable leak category" to weigh for this toolset.)

### Environment: no native Valgrind, same situation as Week 1

Confirmed again rather than re-assumed: Valgrind has no native Windows build. Same fix as Week 1 — Clang/LLVM's ASan+UBSan via MSYS2's `clang64` environment, since GCC's MinGW port has no sanitizer runtime at all (`cannot find -lasan`, same finding as Week 1's `TESTING.md` entry).

**New this week, not needed in Week 1**: `server.c`/`client.c`/`benchmark.c` link against wolfSSL, which is only built for the `UCRT64` environment (per `docs/BUILD.md`) — `clang64` has no wolfSSL of its own. Confirmed empirically that this combination actually works (not assumed): compiled and linked `client.c` under `clang64` against the `UCRT64`-built `libwolfssl.a` via `-isystem /c/msys64/ucrt64/include -L/c/msys64/ucrt64/lib`, then actually ran the resulting binary — it printed its usage message correctly with no ABI-mismatch symptoms. Two real environment issues hit and resolved along the way, neither a code bug:
- **ASan runtime DLL not found at process start** (`libclang_rt.asan_dynamic-x86_64.dll: cannot open shared object file`) — same category of issue as Week 1's own ASan DLL note. Fixed by adding `/c/msys64/clang64/bin` to `PATH` before running any sanitized binary (that's where the DLL actually lives).
- **`undefined symbol: clock_gettime64`** linking `benchmark.exe` specifically (the only file using `<time.h>`'s `clock_gettime()`) — MinGW-w64's UCRT `clock_gettime()` wrapper calls through to a symbol provided by `winpthreads`, which GCC's default link line pulls in automatically but Clang's didn't. Fixed with an explicit `-lwinpthread`.

**Full build line used for every binary this week:**
```bash
export MSYSTEM=CLANG64 && source /etc/profile
clang -Wall -Wextra -g -fsanitize=address -fsanitize=undefined \
  -Iinclude -Isrc -isystem /c/msys64/ucrt64/include -c src/<file>.c -o build_san/<file>.o
clang -g -fsanitize=address -fsanitize=undefined \
  -L/c/msys64/ucrt64/lib -lwolfssl -lws2_32 -lcrypt32 [-lwinpthread for benchmark.exe only] \
  build_san/<objects>.o -o build_san/<binary>.exe
```
`-isystem` (not `-I`) for the UCRT64 include path specifically to suppress a large volume of harmless `-Wpragma-pack` warnings from Windows SDK headers themselves (confirmed harmless — they're about header-internal struct packing pragmas in Microsoft's own headers, not anything in this project's code) while still surfacing any real warning from our own source. Result: **zero warnings across all 9 source files** compiled this way (`server`, `client`, `benchmark`, `message`, `hmac`, `sha256`, `aes128`, `revocation`, `debug`).

### Sanitized unit tests — all 5 binaries, zero findings

```
test_revocation.exe: 8/8 PASS
test_sha256.exe: 3/3 PASS
test_aes128.exe: 12/12 PASS
test_hmac.exe: 4/4 PASS
test_message.exe: 29/29 PASS
```
No ASan or UBSan report on any of the five. This is real coverage `sha256`/`aes128` already had from Week 1 (re-confirmed clean under this week's slightly different toolchain path), plus genuinely new sanitizer coverage for `revocation.c`, `message.c`, and `hmac.c`, none of which had been run under a sanitizer before this week.

### Sanitized integration tests: happy path + full Week 2 negative-test re-run

Same four tests as Week 2 Day 5, same throwaway-PKI artifacts (`~/throwaway-pki/`, which survived from Week 2 and didn't need regenerating), re-run end to end against the **sanitized** `server.exe`/`client.exe` — proving the actual TLS handshake, verify-callback, and revocation-check code paths are memory-safe under real (if synthetic) adversarial certificate input, not just the pure-logic unit tests.

**Happy path** — clean, verbatim:
```
Received TEXT_MESSAGE (seq=0, 25 bytes)
Client message: sanitized happy path test
Received DISCONNECT (seq=1, 0 bytes)
Peer sent DISCONNECT - closing cleanly.
```

**Test 1 (no client cert)** — wolfSSL's own example client, `-x -v 4` (the `-v 4` matters: without it the example client defaults to TLS 1.2, which this TLS-1.3-only server rejects for a *version* mismatch, masking the actual no-cert test — caught this by comparing the rejection reason against Week 2's recorded result before accepting it). Matches Week 2 exactly: `Handshake failed: peer did not return a certificate`, no "checking serial" line (rejected before the verify callback ever runs).

**Test 2 (wrong CA)**, **Test 3 (expired cert)**, **Test 4 (revoked cert)** — all matched Week 2's recorded results exactly (`certificate verify failed` / `ASN date error, current date is after expiration` / `is REVOKED - rejecting` respectively), each rejected for the same specific, distinct reason as before. One behavioral difference worth noting, not a bug: Week 3 Day 2's reconnect-with-backoff logic makes `client.c` retry automatically on a rejection now (it can't distinguish "deliberately rejected" from "transient failure" from its own side), so these negative tests now show 3-4 repeated rejection attempts in the log rather than Week 2's single one-shot attempt — same underlying rejection, just observed multiple times instead of once.

**Confirm nothing broke** — revoked-serials list cleared, server restarted, happy path re-run clean one more time after all four negative tests, same as Week 2 Day 5's own closing step.

**Zero ASan/UBSan reports across every one of these runs.**

### Fuzzing `sl_try_parse_message()` — the one genuinely new tool this week

Initial pass matched the walkthrough's own baseline example (200,000 iterations, 512-byte cap on pure-random buffers, five mutation strategies against one small base message). After that pass completed clean, explicitly asked to make this "super intensive" rather than just meeting the minimum bar — the intensified version below replaced it entirely, run under the same sanitized build (a fuzz loop with no sanitizer underneath only proves "didn't crash," not "is memory-safe" — every run in this section used the ASan/UBSan binary, never the plain one).

**What's more intensive than the baseline pass:**
- 10x the iteration count: 1,000,000 pure-random + 1,000,000 mutated (2,000,000+ total, vs. 200,000 before)
- Pure-random buffers now span the **full valid message-size range** (up to `SL_MAX_MSG_SIZE`, ~64KB) instead of being capped at 512 bytes — the original range barely touched realistic message sizes at all
- Mutation fuzzing now runs against **three base messages of very different sizes** (44-byte, 4KB, and `SL_MAX_BODY_LEN - 1` bodies), not just one ~44-byte message — a bug reachable only on large-message code paths (buffer-boundary arithmetic near the max) would never have been reachable by mutating only a small message
- Three new mutation strategies added (stacked multi-mutation, extreme header field values, `body_length` pushed to exactly its cap or exactly 0) alongside the original five
- A new deterministic fixed-edge-case pass — the same specific boundary inputs (empty buffer, one-byte-short-of-header, all-zero/all-`0xFF` buffers at several sizes, `body_length` at exactly the cap and exactly one over it) run every single time, guaranteed covered rather than left to chance

**Results, verbatim:**
```
  Fixed edge cases             ok=0        rejected=7        incomplete=5        unexpected=0
  Pure random                  ok=0        rejected=985711   incomplete=14289    unexpected=0
  Mutated (3 base sizes)       ok=6586     rejected=700232   incomplete=293181   unexpected=0

Total iterations: 2000011 in 524.85 seconds (3811/sec)
```
Zero "unexpected" (the parser never returned anything outside its own three defined outcomes) across all 2,000,011 iterations. The `ok=6586` on the mutated pass (0.66%) is the same understood, non-concerning phenomenon as the original pass's `ok=1014` — occasional no-op mutations (a `body_length` delta that happens to land on 0, or a stacked bit-flip that cancels itself out) leaving an already-validly-signed message exactly as valid as it started, not a forgery.

**Two real bugs found — both in the fuzz harness itself, neither in `message.c`:**

1. **`global-buffer-overflow`** (from the original, smaller pass): a hand-counted string literal length (`44`) that didn't match the actual string (`42` characters). `sl_serialize_message()` correctly copied exactly the length it was told to; the harness lied about that length. **Fixed** with `strlen()`.
2. **`int-divide-by-zero`** (new, surfaced specifically by the intensified pass's new stacked-mutation strategy — this bug genuinely could not have been found by the original, smaller pass, since it didn't have a stacking strategy at all): the truncation mutation (`len = rand() % (int)len`) could reduce `len` to exactly 0, and a subsequent stacked pass's bit-flip mutation (`rand() % (int)len`) then divided by that zero. **Fixed** by guaranteeing truncation never produces an empty buffer (`len = 1 + rand() % (int)len`) — the empty-buffer case is already covered deterministically by the fixed-edge-case pass, so this doesn't lose any coverage.

Both are exactly the kind of off-by-one/boundary bug this whole exercise exists to catch — just found in the test infrastructure both times instead of the code under test, and both fixed and re-verified clean before being counted as done.

### Network-level fuzzing — a genuinely different test class, added for the same "make it intensive" reason

`tests/fuzz_message.c` calls `sl_try_parse_message()` directly with a pre-assembled in-memory buffer — it structurally cannot exercise how the **real server process** behaves when malformed bytes arrive over an actual socket (TCP fragmentation, `wolfSSL_read()`'s own buffering, the accept loop, `receive_one_message()`'s accumulate-until-complete logic). `tests/fuzz_network.c` closes that gap: connects to an already-running sanitized `server.exe` for real, completes a genuine mTLS handshake, then sends one malformed post-handshake payload per connection (bypassing `sl_serialize_message()` entirely — six payload strategies: pure random, empty write, absurd claimed `body_length` with no body, garbage HMAC tag on an otherwise real-looking header, all-zero minimum-size buffer, and large near-max-payload random data) and confirms the server never crashes. One malformed payload per connection is a structural choice, not a limitation: `server.c`'s own policy is that any single rejected message is fatal to the whole connection, so a second payload on the same connection would never reach the parser again anyway.

**A real bug found in this harness too, this one costing real time rather than tripping a sanitizer**: the first run stalled badly — only 219 of 3000 connections completed after roughly 15-20 minutes. Root cause: several of the random payload strategies can produce a buffer shorter than a complete message, which correctly makes the server block in `wolfSSL_read()` waiting for the rest of a message this harness never sends (it only writes once per iteration) — both sides then wait until the server's own 30-second `SO_RCVTIMEO` eventually forces the connection closed. Not a hang, not a memory-safety bug — a slow harness that didn't need to wait nearly that long to prove what it's actually proving. **Fixed** with a short (2-second) client-side socket timeout, deliberately much shorter than the server's own.

**Full 3000-iteration run after the fix, verbatim:**
```
handshake_failures=0 server_closed_cleanly=3000 write_failures=0

NETWORK FUZZING COMPLETE - this process did not crash.
```
All 3000 handshakes succeeded, all 3000 malformed payloads were rejected and the connection closed cleanly by the server every single time, zero write failures. Server log confirms the expected pattern throughout (`mTLS handshake succeeded.` → `Rejected an invalid message - closing connection.` or `wolfSSL_read: peer sent close notify alert`), and a direct grep of the server's log for `AddressSanitizer`/`UndefinedBehaviorSanitizer`/`ERROR` returned zero hits. Server process confirmed still running (`tasklist`) after all 3000 iterations, not assumed.

**One honest methodology note, not glossed over**: server memory climbed noticeably during this run (roughly 10MB → 293MB) before *decreasing* again (293MB → 191MB → 230MB) over the back half of the run — non-monotonic, which is consistent with ASan's known allocation-quarantine behavior under heavy allocation churn (it deliberately delays reusing freed memory to catch use-after-free bugs) rather than an unbounded leak, but this wasn't independently confirmed with an actual leak-detector report, because it couldn't be: ASan's LeakSanitizer check runs at normal process exit, and `server.c`'s accept loop has no clean shutdown path (a known, already-documented gap from the earlier full-project audit, not new). The memory pattern is suggestive, not proof either way — a real leak-check here needs the graceful-shutdown work already flagged as deferred to Week 4.

### Secrets audit

```bash
grep -rn "print_hex\|printf.*key\|printf.*secret" src/ include/
```
Three hits are file-path logging (`"...cert/key/CA loaded from %s / %s / %s\n"` in `client.c`/`server.c`/`benchmark.c` — these print *paths*, never key *contents*). `print_hex`'s only call sites, checked separately, are all in `tests/` (`test_aes128.c`, `test_hmac.c`, `test_sha256.c`), all against fixed public test vectors, all only printed on a failed assertion — never reachable from `server.c`/`client.c`/`benchmark.c`, which don't call `print_hex` at all. A separate targeted grep for the actual session-key variable (`hmac_key`) near any print function returned zero hits. **Clean.**

### Full regression check

Plain (non-sanitized) build's full five-binary unit test suite re-run once more after all of today's changes: `test_revocation`, `test_sha256`, `test_aes128`, `test_hmac`, `test_message` — all still clean.

### Not yet done (Day 5)
- Valgrind itself, specifically — genuinely unavailable on this platform (no native Windows build), same as Week 1; ASan+UBSan is this project's real substitute here, not a placeholder for "run it on Linux later," though Week 4's Pi hardware will incidentally make real Valgrind available for the first time if it's ever worth revisiting.
- A real leak-detector confirmation for `server.c` under long-running/high-churn conditions — the network fuzz run's memory pattern is suggestive of no leak (non-monotonic, consistent with ASan quarantine churn) but not proven, since that needs a clean process exit `server.c` doesn't support yet (Week 4's graceful-shutdown work, already flagged in the earlier full-project audit).
- `.gitignore` gained a `build_san/` entry (the sanitized-binary output directory) — a small housekeeping fix alongside today's real work, not itself a finding.

## Week 4 prep — FNK0100 auxiliary hardware modules — 2026-08-21

Prototyped ahead of the physical build (Pi hardware exists but has no OS installed yet), per an explicit request to get as much done as possible before Week 4 Day 1. **Read this whole section's status carefully before trusting anything in it as "working"**: everything here is Linux-only code (`/dev/i2c-1`, `<linux/i2c-dev.h>`, `fork()`/`execlp()`) with genuinely zero Windows equivalent, so **none of it has been compiled, let alone run, against anything real** — not even a syntax check (WSL setup was attempted and blocked on requiring admin elevation, a browser-style approval only the user can give, same category as the Tailscale login and Smart App Control situations earlier in this project). What follows is careful manual review and cross-referencing against real, sourced external references, not a test result.

### `hw_expansion.c`/`.h` — case RGB status light

I2C control (address `0x21`, bus 1) for the FNK0100's onboard expansion board (a Nuvoton MS51FB9AE microcontroller). Register map (`REG_LED_ALL=0x02`, `REG_LED_MODE=0x03`, etc.) pulled directly from Freenove's own published reference implementation (`api_expansion.py` in [Freenove/Freenove_Computer_Case_Kit_for_Raspberry_Pi](https://github.com/Freenove/Freenove_Computer_Case_Kit_for_Raspberry_Pi)), not guessed from the product description. `HW_STATUS_DISCONNECTED`/`CONNECTING`/`CONNECTED` map to red/amber/green.

**One specific technical risk checked rather than assumed**: whether a raw `write()` to the I2C character device (this file's approach) produces the same on-wire bytes as Freenove's Python reference code, which uses `smbus.write_i2c_block_data()`. Confirmed against the actual Linux kernel SMBus protocol documentation (`docs.kernel.org/i2c/smbus-protocol.html`): "I2C Block Write" (what `write_i2c_block_data()` maps to) has wire format `Comm [A] Data [A] Data [A] ...` — explicitly no count byte, unlike the *standard* SMBus "Block Write" protocol — which is exactly what a raw `write()` of `[reg, data...]` produces. Verified against the protocol spec, not hardware.

Wired into `client.c`'s reconnect loop and `server.c`'s accept loop (amber while attempting a handshake, green while an mTLS session is live, red otherwise). Compiles clean on Windows as an empty translation unit (`#ifdef __linux__` guards the whole file); the header provides no-op `static inline` stubs on non-Linux so `client.c`/`server.c` call `hw_expansion_*()` unconditionally without their own platform guards. **Live-tested that this wiring doesn't disturb the actual protocol**: full client/server exchange after wiring, byte-for-byte identical to before.

### `hw_oled.c`/`.h`/`hw_oled_font.h` — native SSD1306 driver

128×64 monochrome OLED, I2C address `0x3C` (confirmed via Freenove's `api_oled.py`, which uses `luma.oled.device.ssd1306` at that address). Text-only API (`hw_oled_draw_text(fd, line, text)`, 8 lines × 21 characters), since that's this project's actual requirement, not general graphics.

**Font data**: the classic 5×7 bitmap font (256 characters × 5 bytes), copied **programmatically, not hand-retyped**, from Adafruit's own MIT-licensed [Adafruit-GFX-Library](https://github.com/adafruit/Adafruit-GFX-Library) (`glcdfont.c`) — confirmed exactly 1280 bytes extracted (`grep -c` on the hex literals), matching 256×5 exactly. Fabricating bitmap font bytes from memory was a real, specific risk worth avoiding here: a wrong byte would produce a silently garbled character, invisible without real hardware to look at.

**Init sequence**: traced byte-for-byte against Adafruit_SSD1306's actual `begin()` source and its `SSD1306_*` command constants (both fetched directly), for the specific 128×64/internal-charge-pump configuration these small I2C OLED modules use. Manually counted as 26 bytes; **caught my own arithmetic being worth double-checking** and confirmed the real count by actually compiling a standalone test with `sizeof()` rather than trusting the hand count.

Framebuffer approach: one 8-page × 128-column static buffer (matches the SSD1306's native GDDRAM layout in horizontal addressing mode), flushed to the display in 32-byte I2C write chunks (a conservative, widely-used chunk size, rather than assuming the full 1024-byte buffer fits in one I2C transaction on every adapter). Compiles clean on Windows (empty translation unit), including the embedded font header standing alone (`sizeof(hw_oled_font) == 1280`, checked by actually compiling and running a tiny test program, not asserted).

### `hw_tts.c`/`.h` — optional text-to-speech

Simplest of the three: the FNK0100's speakers are standard analog/optical audio out through the Pi's normal audio path (confirmed in Freenove's own component documentation — no I2C or other custom protocol for the speakers themselves), so this is `fork()`/`execlp("espeak-ng", ...)`, not a hardware register protocol.

**One real correctness issue caught and fixed before it ever became a bug**: a naive single `fork()`+`exec()` with no `wait()` at all (since this needs to be fire-and-forget — never block message handling on speech synthesis finishing) would leave a zombie process table entry behind every time a message is spoken, for the entire life of the long-running server process — a real, if slow, resource leak. Used the standard double-fork technique instead: an intermediate child forks the actual `espeak-ng` process and exits immediately, orphaning it to be reaped automatically by init; the parent's single `waitpid()` call returns almost instantly (reaping the intermediate child, not waiting on speech synthesis).

### Wired into `server.c` for real message notifications

On an incoming `TEXT_MESSAGE`: a bounded, `NUL`-terminated preview (`msg.body` is length-prefixed per `PROTOCOL.md`, not a C string, so a real copy is made first — passing `msg.body` directly to either the OLED or TTS call would be a bug) is drawn to the OLED (`"New message:"` / preview text) and spoken aloud. **This is server-side only** — a genuine design question left open, not silently decided: this project's current protocol is asymmetric (client sends `TEXT_MESSAGE`, server echoes an `ack:` reply), so "new message from the other party" is unambiguous on the server side today. If the protocol ever becomes genuinely bidirectional, `client.c` would need the same wiring, which hasn't been added since that's a real design decision, not something to add speculatively.

**Live-tested that this wiring doesn't disturb the actual protocol** (same as the RGB wiring): full client/server exchange, byte-for-byte identical server/client output to before the notification code existed. Full five-binary regression suite re-run clean.

### Not yet done / explicitly deferred
- All real hardware verification — everything above needs to actually run on the Pi with the real case attached before any of it can be called "working." Do not report this as tested or working anywhere until that's genuinely happened. **Update, same day (see Week 4 Day 1 section below): the compile-only part of this is now resolved** — `hw_expansion.c`/`hw_oled.c`/`hw_tts.c` have genuinely compiled clean on real Linux for the first time. Real I2C peripheral behavior (the OLED actually rendering text, the RGB light actually changing color) is still unverified — I2C hasn't been enabled via `raspi-config` yet.
- Fan speed control (`REG_FAN_MODE`/`REG_FAN_DUTY`, same expansion board) — not built, wasn't asked for (the request was specifically RGB-for-status, not cooling control).
- Confirming `espeak-ng` is actually available on Raspberry Pi OS's default package repos — still not independently confirmed (not installed yet).

## Week 4, Day 1 — Real Pi hardware bring-up — 2026-08-21

First time this project has run on its actual deployment target. Two Raspberry Pi 5 (4GB) in FNK0100 cases, `securelink-alpha` and `securelink-bravo`. Executed directly via SSH from the dev machine (both Pis reachable on the same LAN as the dev laptop) rather than relayed as instructions — every step below was actually run and its real output checked, not assumed from a command's exit code alone where a real check was possible.

### Flashing and first boot
Raspberry Pi OS Lite (64-bit), SSH key-only auth and WiFi credentials baked in at image time via Raspberry Pi Imager's advanced options (avoids the classic headless-lockout risk of configuring this after first boot). A dedicated SSH key (`~/.ssh/securelink_pi`, ed25519) was generated specifically for this rather than reusing any other key. Both units reachable via `securelink-alpha.local`/`securelink-bravo.local` (mDNS) on first attempt.

### A real hardware assembly issue, found and fixed before any software work started
One unit wouldn't power on via the case's own exterior USB-C port while the other worked fine. Isolated methodically using the working unit as a reference rather than guessing: power supply swap (cleared the supply as a cause), then the bare-Pi-outside-the-case test (confirmed the Pi board itself and the case's adapter/header board were both fine — powering the Pi directly also powered everything downstream correctly). Root cause found by reading Freenove's actual assembly manual (`Tutorial.pdf`, extracted via `pdftotext`) rather than guessing at cable layouts: the case's exterior Type-C port isn't a separate cable — the Pi 5's own Type-C/HDMI0/HDMI1 ports plug **directly into matching connectors on the Case Adapter Board** via precise board-to-board alignment. Re-seating that alignment fixed it.

### SSH hardening — confirmed already correct from first boot, not something that needed fixing
Checked the *effective* runtime sshd config (`sudo sshd -T`), not just grepped the raw config file (a raw grep of `sshd_config` alone was inconclusive — only showed `KbdInteractiveAuthentication no`, a different setting from `PasswordAuthentication`). Effective config on both: `passwordauthentication no`, `pubkeyauthentication yes`. **Proved the negative case empirically, not just trusted the config**: an explicit password-only SSH attempt (`-o PreferredAuthentications=password -o PubkeyAuthentication=no`) was genuinely rejected (`Permission denied (publickey)`) on both — same "prove the rejection, don't just assume it" discipline as Week 2 Day 5's negative tests.

### Passwordless sudo — a deliberate, explicit decision, not a default
Needed for the rest of Day 1's automation. User explicitly declined to share their account password (correctly — a password typed into a chat session sits in plaintext history indefinitely, for zero benefit over the alternative); instead ran a one-time bootstrap themselves per-Pi (`echo "connor ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/010-connor-nopasswd`, validated with `visudo -c` before trusting it). Confirmed working (`sudo -n true`) on both before relying on it for anything.

### System update, dependencies, native wolfSSL build — all real, all verified
- `apt update`/`apt upgrade -y`: 95 packages on each, included a kernel update (6.18.34 → 6.18.39), clean on both, no errors.
- Build dependencies (`build-essential libncurses-dev git autoconf automake libtool pkg-config`): clean install on both.
- wolfSSL cloned fresh from the official upstream repo (no version pinned in this project's own docs, so current release was the sensible default) and built natively with the same flags as the dev-machine's Week 3 Day 2 rebuild (`ac_cv_vcs_checkout=no --enable-static --disable-shared --enable-debug --prefix=/usr/local --enable-opensslextra --enable-keying-material CPPFLAGS=-DWOLFSSL_HAVE_ERROR_QUEUE`) — every one of those flags exists because of a specific, previously-diagnosed problem, so all were carried forward rather than re-discovered the hard way. Configured, built (`make -j4`), and installed cleanly on the **first attempt** on both — notably, the `ac_cv_vcs_checkout=no`-guarded `-Werror`/modern-GCC interaction that caused real trouble on the Windows/MSYS2 dev-machine build never recurred here (defensively included anyway; harmless if unneeded).
- Verified for real, not assumed: `grep HAVE_KEYING_MATERIAL /usr/local/include/wolfssl/options.h` and `nm /usr/local/lib/libwolfssl.a | grep export_keying_material` both confirmed present on both Pis.

### Full SecureLink codebase — first native ARM build, first native ARM test run

Cloned from `github.com/ConnorY-MSU/SecureLink` at the latest commit (`35f9490`, includes the Week 4 hardware modules). Compiled every source file with `gcc -Wall -Wextra -g` — **zero warnings, zero errors, on the first attempt, on both Pis**, including `hw_expansion.c`/`hw_oled.c`/`hw_tts.c`, which had never been compiled at all before this moment (no Windows equivalent existed to even syntax-check them against — this was the actual, real resolution of that open item from earlier today's "Week 4 prep" section).

**All 5 unit tests, run natively, verbatim, both Pis:**
```
test_sha256:     ALL VECTORS PASSED
test_aes128:     ALL VECTORS PASSED
test_revocation: ALL VECTORS PASSED
test_hmac:       ALL VECTORS PASSED
test_message:    ALL VECTORS PASSED
```
Identical to every dev-machine run of the same tests — no ARM-specific behavioral differences found (endianness, struct padding, or compiler-default differences were all things worth checking for per the walkthrough's own guidance; none surfaced).

`server`, `client`, and `benchmark` also compiled and linked clean. Running them confirmed the hardware modules' absence-handling works exactly as designed in practice, not just in review: `hw_expansion_open`/`hw_oled_open` both logged `cannot open /dev/i2c-1 (case hardware absent or I2C not enabled? continuing without it)` and the server kept running normally — I2C hasn't been enabled via `raspi-config` yet (next real step for that work, per the Week 4 Build Log's own checklist).

### First genuine two-device network test this project has ever had

`alpha` as server, `bravo` as client, real WiFi LAN (not loopback, not localhost) — using the existing, already-trusted dev-machine cert pair (deliberately: the CA private key never touched either Pi, matching Week 2's own PKI design; only `server_cert.pem`/`server_key.pem`/`ca_cert.pem` went to `alpha`, only `client_cert.pem`/`client_key.pem`/`ca_cert.pem` went to `bravo`). Verbatim, both sides:
```
Client (bravo): Connected to server. / mTLS handshake succeeded. / Server: ack: hello from bravo, the real deal!
Server (alpha): Verify callback: serial ... not revoked, proceeding. / mTLS handshake succeeded.
                Received TEXT_MESSAGE (seq=0, 32 bytes) / Client message: hello from bravo, the real deal!
                Received DISCONNECT (seq=1, 0 bytes) / Peer sent DISCONNECT - closing cleanly.
```
Note: generating genuinely separate per-device PKI identities for `alpha`/`bravo` (each with its own key, its own CSR signed by the dev-machine CA) rather than reusing the existing shared test-cert pair is still open — reasonable for today's connectivity proof, but worth doing properly (matching the Day 6 rotation-drill pattern) before calling device identity "real."

### Tailscale on real hardware
Installed and authenticated on both (interactive browser approval, necessarily done by the user — same category as every other browser-auth step this project has hit). Real Tailscale IPs assigned (`100.124.177.123` / `100.103.41.44`). `tailscale ping` confirmed a genuine **direct peer-to-peer path** (not relayed through DERP): `pong from securelink-bravo ... via 192.168.113.214:41641 in 27ms`.

**ACL tags applied and verified**, extending Week 3's already-pasted policy: `alpha` → `tag:securelink-server`, `bravo` → `tag:securelink-client`, confirmed via `tailscale whois` on both (not just trusted from the `up` command's exit code — same discipline as Week 3's dev-machine tagging). Dev machine keeps its own `tag:securelink-client` for now (deliberate choice, to allow continued dev-machine-to-Pi testing during development) — revisit before considering the project's real deployed pair finished, since the actual end-state shouldn't need the dev machine in this ACL.

Key expiry disable for both devices: handed to the user (admin-console-only, no CLI equivalent) — not yet confirmed done.

### NetworkManager confirmed — with one genuinely new detail
`systemctl is-active NetworkManager` → active, `nmcli device status` shows `wlan0` managed correctly on both. **New finding, not anticipated by the original Bullseye-vs-Bookworm dhcpcd-vs-NetworkManager framing**: the WiFi connection profile is named `netplan-wlan0-BDH-public` — this OS image layers **netplan on top of NetworkManager** (netplan generates the NM profile), not NetworkManager acting fully standalone. `nmcli` should still work fine for Days 2-3's WiFi setup screen (it manages NetworkManager connections directly regardless of who created them), but a profile added purely via `nmcli` might not be reflected back into netplan's own config — worth verifying specifically when Days 2-3's WiFi setup screen is actually built, not assumed fine by analogy.

### Console auto-login and full reboot verification
`raspi-config nonint do_boot_behaviour B2` on both; verified the actual systemd override file exists and targets the right user (`ExecStart=-/sbin/agetty --autologin connor ...`) rather than trusting the command's exit code alone. Both Pis rebooted for real (not just the config checked) — full verification after reboot, all real, all checked:
```
kernel:        6.18.39+rpt-rpi-2712 (confirms the earlier apt upgrade's kernel update took effect)
auto-login:    connor  tty1  <reboot timestamp>  (zero manual login)
sudo:          passwordless, survived reboot
tailscale:     Running, both peers visible, reconnected automatically with no manual re-auth
build/:        all artifacts survived (server, client, test_message, etc. all present)
```

### Not yet done (Day 1)
- Key expiry disable for both Pis in the Tailscale admin console — handed to the user, not yet confirmed.
- Per-device PKI identities for `alpha`/`bravo` (currently reusing the shared dev-machine test cert pair for the connectivity proof) — real, worth doing, not done today.
- `espeak-ng` not yet installed on either Pi.

## Loose-end close-out — real I2C hardware verification — 2026-08-21

`raspi-config nonint do_i2c 0` on both — `/dev/i2c-1` present immediately on both, no reboot needed. `i2c-tools` installed, `sudo i2cdetect -y 1` run on both — **both expected addresses responded, exactly matching what the code was written against, not assumed**:
```
20: -- 21 -- -- -- -- -- -- -- -- -- -- -- -- -- --
30: -- -- -- -- -- -- -- -- -- -- -- -- 3c -- -- --
```
(`0x21` = FNK0100 expansion board, `0x3c` = SSD1306 OLED — identical on both Pis.)

**Ran `server` on `alpha` for real, against real silicon, for the first time.** No I2C errors in the log at all (previously, before I2C was enabled, both `hw_expansion_open` and `hw_oled_open` logged and continued gracefully — now both succeeded silently). Per the code, this means `HW_STATUS_DISCONNECTED` (red) was written to the RGB light and the full SSD1306 init sequence plus `"SecureLink server"` / `"Waiting..."` were written to the OLED.

**User visually confirmed, in person, on the real device**: OLED genuinely displaying `"SecureLink server" / "Waiting..."`, RGB light genuinely red. Exact match to the code's design, on the very first real-hardware attempt — the I2C wire-protocol reasoning (cross-checked against the kernel's own SMBus docs), the FNK0100's register map (sourced from Freenove's own code), the SSD1306 init sequence (traced from Adafruit's own source), and the embedded font table (copied programmatically, not retyped) all turned out correct with zero fixes needed.

**Dynamic behavior also confirmed for real**, not just the static at-rest state: connected `bravo`→`alpha` (this time over the real Tailscale connection, `100.124.177.123`, not just LAN) and held the session open for ~20 seconds specifically so the user could watch the transition, not just infer it from a fast exchange. **User confirmed both units' RGB lights went green while connected** (`HW_STATUS_CONNECTED`, correctly triggered on both the client and server side).

**One real, expected asymmetry found and confirmed by the user in person**: `bravo`'s OLED stayed dark the whole time. Checked why rather than assumed: `client.c` only ever includes `hw_expansion.h` (RGB), never `hw_oled.h` — this was today's earlier deliberate design decision (OLED notifications wired server-side only, since the protocol is currently asymmetric: client sends, server receives/replies). **Explicitly re-decided, not left as an open question, now that it was visible in person**: staying server-side only for now, revisit if/when the protocol becomes genuinely bidirectional.

**Net result: every piece of the FNK0100 hardware work built "blind" earlier today is now confirmed working against real hardware, zero fixes needed.** This is a genuinely rare, clean outcome for code that could never be compiled, let alone tested, before this exact session — worth stating plainly rather than downplaying.

## Symmetric two-way communication redesign — 2026-08-21

Following the OLED asymmetry finding above, the user reconsidered the protocol shape itself: **"wait i want it to be symetric, both contact both. two-way communication"** — not client-sends/server-echoes with an auto-generated "ack: " reply, but a real chat where either side can type and send at any time, and both sides display incoming messages the moment they arrive regardless of whether the local user is actively typing. Design decisions made explicitly (via direct choice, not assumed):
- **Concurrency: threads**, not non-blocking I/O — one thread permanently dedicated to receiving, the calling thread free to poll stdin.
- **Timing: now**, at the client.c/server.c level — not deferred into the Days 2-3 ncurses UI work.
- **Server autonomy: "receiving always works, replying is optional"** — the server must keep displaying/logging incoming messages with zero human present (preserving this project's zero-manual-steps unattended-operation goal), but a human *can* type a reply at any time if one is at the keyboard.

### wolfSSL thread-safety, researched before any code was written
wolfSSL's own docs/forums are explicit: concurrent `wolfSSL_read()`/`wolfSSL_write()` on the *same* `WOLFSSL*` from two threads is unsafe (single shared I/O buffer). Fix: `wolfSSL_write_dup(WOLFSSL*)` (needs `HAVE_WRITE_DUP` / `--enable-writedup`) — turns the original object read-only and hands back a genuinely separate write-only object. Rebuilt wolfSSL with this flag on **all three machines** (dev, `alpha`, `bravo`) and confirmed via `nm ... | grep write_dup` showing the real compiled symbol on each, before writing any session code against it.

A second, less obvious thread-safety issue found and fixed during design (not by trial and error): a receiver thread (auto-replying PONG to an incoming PING) and the local user's send both go out through the *same* write-dup'd object — splitting "serialize the message" and "write it to the wire" into two separate critical sections would let one thread's write reach the wire out of seq_num order, or worse, let two `wolfSSL_write()` calls genuinely interleave mid-record. Fixed by having a single `send_mutex` in `session.c` wrap the entire serialize+write pair as one atomic unit, for either sender. Never held around the receiver's blocking `wolfSSL_read()` — an idle peer can't stall the ability to type and send.

### Architecture
`include/session.h` / `src/session.c` — a new, genuinely shared module (`run_symmetric_session()`), used identically by both `client.c` and `server.c` — a deliberate deviation from this project's established "duplicate small glue functions rather than share them" convention, justified by the size (~200 lines) and thread-safety-criticality of this specific piece (see `session.h`'s own design comment for the full reasoning). `client.c`'s old `run_interactive_session()` (609→~470 lines) and `server.c`'s old `handle_connection()` (678→~430 lines) — including the auto-"ack: "-echo behavior — are gone entirely, replaced by a single call into `run_symmetric_session()`. Client-side OLED (`hw_oled.h`) is wired in for the first time as part of this change — the earlier server-side-only OLED decision was explicitly tied to the old asymmetric protocol, which no longer exists.

### Dev-machine build verification
`session.c` compiles clean (`-Wall -Wextra`, zero warnings) standalone and linked into both `client.exe`/`server.exe` on the Windows/MinGW dev machine, `-lpthread` added to both link lines. Confirms winpthreads (MinGW-w64's real POSIX pthread implementation) works for this code, not just a synthetic test program.

### Real two-Pi-hardware verification — full pass, first attempt
Copied the four changed/new files to both Pis' existing checkouts (git history not yet caught up to this — see below) and built natively on both:
```
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/session.c src/client.c src/server.c
gcc ... -o build/server ... -lwolfssl -lpthread -lm
gcc ... -o build/client ... -lwolfssl -lpthread -lm
```
**New, previously-undocumented Linux-vs-Windows link requirement found**: linking against `libwolfssl.a` on Linux needs `-lm` explicitly (`DiscreteLogWorkFactor()` in `wolfcrypt/src/dh.c` calls `pow()`/`log()`) — Windows's link line never needed this. Not related to the pthread work at all; just never surfaced until this was the first time this exact object set was linked fresh on the Pi.

Ran a real, live, timed two-way exchange between the two physically separate Pis (`alpha` as server, `bravo` as client, real LAN via mDNS resolution — same setup as the earlier real-hardware connectivity proof), each side's stdin fed through a FIFO with scripted timed writes to simulate a human typing without needing two people at two keyboards simultaneously. Actual captured output, both sides, unedited:

**`alpha` (server) log:**
```
mTLS handshake succeeded.
Connected to client. Type a message and press Enter (or 'quit' to exit).
Incoming messages from client display automatically at any time.
client: hello from bravo (client)
client sent DISCONNECT.
Connection to client lost.
```

**`bravo` (client) log:**
```
mTLS handshake succeeded.
Connected to server. Type a message and press Enter (or 'quit' to exit).
Incoming messages from server display automatically at any time.
server: hello from alpha (server)
server: second message from server
```

Confirms, on real hardware, all at once:
- **No auto-ack** — the server's log shows the client's message arriving with no "ack: " reply generated (compare to the Day-1-era log further up this file, where `handle_connection()` still auto-echoed).
- **"Receiving always works, replying is optional"** — `bravo` displayed both of `alpha`'s messages (sent at the server's own pace) without `bravo`'s own send loop being involved at all; `alpha` displayed `bravo`'s message the moment it arrived, independent of whatever `alpha`'s own scheduled input was doing.
- **`wolfSSL_write_dup()` genuinely safe under real concurrent use** — the receiver thread was reading continuously on both machines while each machine's own send path was independently active; zero corruption, zero garbled frames, zero HMAC/seq_num rejections in either direction.
- **Clean quit propagation** — `bravo`'s "quit" produced a real `DISCONNECT` the server received and handled correctly (`client sent DISCONNECT.` / `Connection to client lost.`), and `bravo`'s own process exited cleanly (exit code 0) rather than hanging or needing to be killed.

**Not yet visually confirmed**: whether the client-side OLED wiring (new this session) actually renders on `bravo`'s screen during a real session — the test above only captured console/log output, not what's physically on either screen. Also not yet re-tested: `bravo`'s touchscreen cable check and the coordinated reboot the user asked for before this redesign work started — still outstanding from before this section.

**Repo sync note**: this test ran against files copied directly (`scp`) into each Pi's existing checkout, deliberately ahead of committing — consistent with this project's discipline of proving something works before documenting/committing it as done. Committed as `5848d8d`, pushed, and both Pis' git checkouts pulled clean at that commit the same day.

## Real hardware follow-up — DSI console-binding fix, speaker confirmation, and a real timeout bug found in the two-way redesign — 2026-08-21

Same day, continued session, after the user got both touchscreens physically working.

### `alpha`'s touchscreen: not a hardware fault, a DRM enumeration-order coincidence
After both Pis were rebooted, `bravo`'s touchscreen showed console text correctly but `alpha`'s stayed on/backlit with nothing displayed. Diagnosed properly rather than re-checking cables again: both Pis' DSI panels were detected fine at the kernel level (`card1-DSI-2: connected`, `/dev/fb1` present, `rp1dsi_bind succeeded` in `dmesg` — identical on both). The actual difference: **which physical output got numbered `fb0` vs `fb1` by the DRM/KMS driver differs between the two otherwise-identical boards** — a probe-order coincidence, not a fault:
- `bravo`: `fb0` = DSI touchscreen, `fb1` = HDMI. Console (`con2fbmap 1` → framebuffer 0) lands on the touchscreen → works.
- `alpha`: `fb0` = HDMI (nothing plugged in), `fb1` = DSI touchscreen. Console lands on HDMI, going nowhere visible, while the touchscreen sits powered but blank.

Fixed live with `sudo con2fbmap 1 1` (remaps VT1 to `fb1`) — confirmed by the user immediately after. **Not yet made persistent across reboots** — since the fb0/fb1 assignment is enumeration-order-dependent and not guaranteed stable, a numeric `fbcon=map:N` kernel parameter would be just as fragile; the durable fix needs a boot-time script that identifies the DSI framebuffer by name (`drm-rp1-dsidrmf` via `/sys/class/graphics/fb*/name`) rather than by index, and remaps dynamically. Flagged as follow-up work, not done yet.

### Speaker test: confirmed working, with a real driver/wiring subtlety understood first
`aplay -l` showed only the two HDMI ALSA codecs, no dedicated case-speaker device — expected, not a bug: per Freenove's own documentation ([FNK0100 docs](https://docs.freenove.com/projects/fnk0100/en/latest/), confirmed via web search rather than assumed), the Raspberry Pi 5 removed its onboard analog audio jack entirely, so the case's Case Adapter Board doesn't have its own DAC — it electrically taps the HDMI audio signal instead ("audio separation circuit"). A known GitHub issue ([Freenove/Freenove_Computer_Case_Kit_for_Raspberry_Pi#4](https://github.com/Freenove/Freenove_Computer_Case_Kit_for_Raspberry_Pi/issues/4)) reports other users hitting silent output tied to a `vc4_hdmi.c` "Packet RAM" kernel warning on Pi 5 — checked for it first (`dmesg | grep -i 'packet ram\|infoframe'` — none present on `alpha`). Ran `speaker-test -D plughw:0,0` (HDMI0's codec) — **user confirmed audible sound** on the second, longer attempt. `espeak-ng` was already installed on both Pis (a Day-1 loose end resolved without extra action needed).

### A real bug found and fixed: spurious ~30-second disconnects during idle periods
Testing the two-way redesign with the physical OLEDs in mind (holding a session open longer so the user could walk over and look at both screens) surfaced a genuine bug: a live two-way session between `alpha` and `bravo` disconnected and reconnected several times within under a minute of real idle time, with the server repeatedly sending an unprompted `DISCONNECT`.

**Root cause, confirmed by reading the code, not guessed**: `client.c`/`server.c` both call `set_socket_timeout()` (`SO_RCVTIMEO` = `CONN_TIMEOUT_SECONDS` = 30s) on the raw socket *before* the TLS handshake, to bound a stalled connect/handshake attempt. That made sense for the old synchronous send-then-wait-for-one-reply protocol, where a long idle read genuinely meant something was wrong — but it was never cleared afterward, so it stayed in effect for the receiver thread's entire life under the new design. Under "receiving always works," the receiver thread blocking in `wolfSSL_read()` for a long time during a normal idle chat is *expected*, not a failure — but `receiver_recv_one()` in `session.c` treated any `wolfSSL_read()` returning ≤0 (including a benign `SO_RCVTIMEO` expiry, indistinguishable at that call site from a real closed connection) as `RTHREAD_RECV_CLOSED`, ending the session roughly every 30 seconds of real idle time.

**Fix**: `run_symmetric_session()` now clears `SO_RCVTIMEO` on the raw socket (to 0 / infinite) as its first action, before starting the receiver thread — see `session.h`'s "IMPORTANT for callers" comment for the full reasoning, including why `SO_SNDTIMEO` is deliberately left untouched (a stuck *send*, unlike an idle read, staying blocked for 30s is still a legitimate "something's wrong" signal, and is what's left providing dead-network detection now).

**Verified via a real, timestamped 50-second idle test between the two physical Pis** — connection held healthy continuously from handshake (`t=7`) through the full ~47 seconds of idle time, well past where the old bug would have killed it around `t=30`–`37`:
```
[t=7]  mTLS handshake succeeded.
[t=11] client: hello from bravo t=5
[t=55] (still the same session - killed only by the test's own 55s external timeout)
```
Rebuilt and redeployed to both Pis, confirmed clean compiles (`-Wall -Wextra`) on both before retesting.

## Week 4, Days 2-3 (Parts A-D) — ncurses UI layer — 2026-08-21

Real design decisions made and documented in `include/ui.h`'s top comment, per `ncurses UI Concepts.md`:
- **Concurrency**: reuses `session.c`'s existing threaded design (receiver thread + polling sender loop) rather than a second, competing concurrency model - the walkthrough's "Option 1, single non-blocking loop" was considered and deliberately not chosen, since it would mean re-deriving the same thread-safety work already done for wolfSSL for no benefit.
- **Windows**: three separate `WINDOW*`s (status/history/input), matching the walkthrough's own given layout.
- **Scope**: the UI is active for the whole process lifetime (`ui_init()` called once in `main()`), not just per-connection, so the status bar can show connecting/disconnected states between sessions too - a device meant to sit in a case should always show something coherent, not flip between a plain console and a full-screen UI depending on connection state.
- **Touch**: keyboard-driven; the touchscreen displays the same UI, no on-screen-keyboard text entry - the honest, limited scope `ncurses UI Concepts.md` explicitly sanctions ("touch is used only to..." framing).

New `include/ui.h`/`src/ui.c` module, `__linux__`-gated real ncurses implementation with a non-Linux plain-stdio fallback that replicates exactly what `client.c`/`server.c`/`session.c` did before this module existed (same precedent as `hw_expansion.h`/`hw_oled.h`: dev-machine behavior unchanged). `session.c`'s every `printf`/`fprintf` call was converted to `ui_set_status()`/`ui_add_history()` (and their printf-style `...f()` variants, added specifically so the many existing call sites in `client.c`/`server.c` could convert with a near-mechanical swap) - necessary, not cosmetic: once ncurses is active it assumes exclusive control of the terminal, and any stray direct `printf`/`fprintf` would visually corrupt the screen it manages. Verified this conversion was actually complete (not just "the obvious spots") by grepping both files for every remaining `printf(`/`fprintf(` call before testing.

### Two real bugs found via live two-Pi testing, not caught by compiling alone

**1. Message not rendering - root cause was a test-timing assumption, not a code bug.** First pass looked exactly like a rendering failure: a message would arrive (confirmed via `/proc/<tid>/stack` showing the receiver thread genuinely blocked in `recvfrom()` beforehand, then via temporary debug logging showing `ui_add_history()` being called with the correct data and completing successfully) but not show up in `tmux capture-pane`'s output for several seconds. Resolved by simply waiting longer before checking - not a real defect, a lesson about this specific test methodology's latency, kept here so it isn't rediscovered as a false alarm later.

**2. A real bug: `ui_mutex` starvation.** The *initial* `ui_poll_line()` held `ui_mutex` for the entire `wgetch()` timeout wait (up to `STDIN_POLL_MS`), called back-to-back in a tight loop by `session.c` with almost no gap between one call's unlock and the next call's lock. This starved the receiver thread's `ui_add_history()` calls - confirmed, not guessed, via `/proc/<tid>/stack` showing the receiver thread sitting in `futex_do_wait` on this exact mutex while the main thread's own wait showed as legitimate short `poll()` calls with the lock free for only a sliver of each cycle. Linux's default pthread mutex provides no fairness/FIFO guarantee, and a thread that immediately tries to re-lock right after unlocking has a real, observed tendency to keep winning the race - this wasn't a deadlock (it did eventually resolve, confirmed by waiting), but was observed to persist for 30+ seconds in one run, unacceptable for a chat UI.

**Fix**: `ui_poll_line()` now polls in short `UI_POLL_SLICE_MS` (20ms) slices and, critically, `usleep()`s *outside* the lock between slices when nothing was typed - not just a shorter hold, an actual guaranteed window where this thread isn't even attempting the mutex, giving the receiver thread a genuine uncontended chance every ~20ms instead of every ~200ms with almost no gap at all.

**Verified after the fix**: real two-Pi test, message sent from either side rendered on the peer's screen within ~1 second consistently (checked promptly, not by waiting-and-hoping), across multiple rapid back-and-forth exchanges. `quit` on one side produced a real `DISCONNECT` the other side handled correctly, the quitting side's process exited cleanly (confirmed via `ps`), and the surviving side's status bar correctly reset to "Listening on port 4433...".

### Build notes
`ui.c` needs `pkg-config --cflags ncurses` (`-D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600`) specifically for its compile step, and links against `-lncurses -ltinfo` in addition to this project's existing libs. Confirmed via `pkg-config --cflags --libs ncurses` on both Pis rather than assumed. `tmux` was installed on both Pis specifically to drive/inspect the ncurses UI programmatically for this testing (`tmux send-keys` / `tmux capture-pane`) - a testing-only tool, not a project runtime dependency.

### Display hierarchy made explicit — 2026-08-21
Following the user's request, the touchscreen/ncurses UI is now explicitly documented (in `ui.h`'s and `hw_oled.h`'s top comments, and in the build log) as the **primary** display - full status, full history, real interaction. The 128x64 OLED is explicitly **secondary** - small, glanceable, brief-preview-only, never a substitute. This governs what belongs where going forward, not just a naming choice.

## Week 4, Days 2-3 (Part E) — lock screen — 2026-08-21

New `include/lock.h`/`src/lock.c`: salted-hash PIN storage using the project's own Week 1 `sha256.c` (a legitimate, deliberate use of the hand-rolled primitive in the shipped product - see `lock.h`'s comment). Pure logic, no ncurses dependency at all, verified in isolation first via a throwaway ad-hoc test program (set/check/wrong-PIN/wrong-length/overwrite, all passed) before touching `ui.c` - the same "isolate before integrate" discipline used throughout this project.

Real decisions made and documented in `ui.c`'s lock-screen block comment, per `ncurses UI Concepts.md`:
- **Hidden/visible**: message history and the compose line hidden while locked; status bar (connection state) stays visible and untouched by lock state.
- **Entry point**: Ctrl+L, one discoverable keybinding doing double duty - "lock now" if a PIN exists, "start setting a PIN" if none does yet. A device with no PIN configured starts unlocked with an in-history hint, rather than demanding PIN setup before it's otherwise usable.
- **Lock timing**: locked by default on boot whenever a PIN has ever been set; 120-second inactivity auto-lock otherwise (reasoning: long enough not to interrupt someone actively reading/replying, short enough that walking away doesn't leave content exposed for long).
- **Rate limiting**: yes - a short, increasing delay (1s, 2s, ... capped at 5s) after each wrong PIN, even though the actual threat model (physical possession already required to reach this screen at all) doesn't strictly demand it - cheap to implement, real speed bump against a scripted/macro attempt.
- **Decoupling**: the lock-screen state machine touches only ncurses windows and `lock.c` - never a socket, a `WOLFSSL*`, or `sl_session_state*` - so there's no code path by which it could disrupt the network/crypto layer.

**Implementation subtlety worth recording**: hiding history while still receiving requires care with ncurses' own model. `ui_add_history()` always `wprintw()`s into `history_win`'s buffer regardless of lock state (the receiver thread's behavior must never change based on UI state), but only calls `wrefresh()` when NOT locked. The lock overlay is drawn and `wrefresh()`'d once, at lock time, and then simply never gets overwritten on the physical screen (since no further `wrefresh(history_win)` happens) even though real messages keep accumulating in the window's off-screen buffer underneath. Unlocking calls `touchwin(history_win)` before `wrefresh()` - required, not optional, since ncurses' normal diff-based refresh can otherwise miss content that changed while that window wasn't the one being refreshed.

### Verified end-to-end on real two-Pi hardware, including the decoupling proof test the walkthrough specifically asks for
1. First run, no PIN configured: correctly started unlocked with the "No PIN set" hint.
2. Ctrl+L → set PIN flow (enter, confirm, mismatch-retry path all exercised) → "PIN set" confirmation.
3. Ctrl+L again → correctly locked, history hidden, status bar unaffected ("Connected to client" stayed visible).
4. **Sent a real message from `bravo` while `alpha` was locked** - `alpha`'s screen stayed on the lock prompt throughout, exactly as designed.
5. Wrong PIN on `alpha` → correct rate-limit message ("Wrong PIN (wait 1s before next try)").
6. Correct PIN after the cooldown → unlocked, and **the message that arrived while locked was immediately visible** - the actual decoupling proof.
7. Sent one more message each direction after unlocking - connection fully healthy, nothing about the lock cycle degraded it.

### A real architecture gap found via this testing, not yet resolved
Ctrl+L and typed characters appeared to do nothing on the very first attempt - not a lock-screen bug: `ui_poll_line()` (and therefore all lock-screen interaction, including first-time PIN setup) is only ever called from *inside* `run_symmetric_session()`'s sender loop, which doesn't exist until a connection is established. `server.c`'s accept loop blocks in `accept()` indefinitely with no input polling at all while waiting for a peer; `client.c`'s reconnect loop is similarly unresponsive during its backoff sleep. Confirmed by reproducing: input sent before a connection existed sat queued in the pty and was only processed once `bravo` connected and `run_symmetric_session()` started reading it.

**Practically**: on this project's real target topology (two Pis on the same Tailscale mesh, normally connected to each other most of the time), this mostly affects the boot-up window before the first connection lands and any reconnect gaps - not the steady state. But it's a real, honest limitation for a device meant to work as a standalone kiosk: someone can't set up or check a PIN, or manually lock the screen, while the device happens to be disconnected.

### Fixed the same day: a dedicated idle-input thread
`ui_start_idle_input()`/`ui_stop_idle_input()` (`ui.h`/`ui.c`): a dedicated thread that runs `ui_poll_line()` in a loop whenever no session is active, servicing the exact same lock-screen keys an active session's sender loop would. Turned out simpler than initially expected: `server.c`'s blocking `accept()` didn't need restructuring into something pollable at all, since the idle thread runs concurrently with it on its own thread rather than needing the main thread to interleave input checks - `ui_mutex` (already in place for the receiver-thread/sender-loop coordination) serializes the third caller too, with no new conflicts.

The two functions are temporally mutually exclusive with an active session by construction - `client.c`'s `connect_and_run()` and `server.c`'s accept loop each bracket their `run_symmetric_session()` call with `ui_stop_idle_input()` immediately before and `ui_start_idle_input()` immediately after, so the idle thread and the session's own receiver-thread/sender-loop pair never both read `input_win` at once. A line "submitted" while idle (Enter pressed with nothing to send it through) shows "(not connected - nothing sent)" in history rather than silently vanishing.

**Verified end-to-end on real hardware, the exact gap scenario from before**:
1. Server started, no client connected at all - Ctrl+L worked immediately (previously did nothing until a client connected).
2. Set a PIN entirely while disconnected (both entry steps) - worked.
3. Locked the screen while still disconnected - worked.
4. Connected a client while already locked-and-idle - status bar updated to "Connected to client", lock state correctly preserved (screen stayed locked, did not reset to unlocked on connect) - confirms a clean handoff from the idle thread to the session's own input handling with no lost state.
5. Sent a message from the peer while alpha was locked (having been locked since before the connection existed) - stayed locked, unlocked with the correct PIN, message was there - the same decoupling proof as before, now confirmed starting from the idle state too.
6. Client quit, connection ended - status correctly reset to "Listening on port 4433...", input line back to normal compose mode.
7. Ctrl+L worked again immediately - confirms the idle thread properly resumed after the session ended, not just started once at boot.

### Not yet done (Days 2-3, remaining)
- Whether/how the RGB status light and OLED hook into this new ncurses UI, rather than remaining a separate layer - still an open question carried forward from Day 1.

## Week 4, Days 2-3 (Part H) — WiFi setup screen — 2026-08-21

New `include/wifi.h`/`src/wifi.c`: a thin wrapper around `nmcli`, used by a new WiFi setup mode in `ui.c`. Every `nmcli` invocation goes through `fork()`+`execvp()` with an explicit argv array - deliberately never `system()`/`popen()` with a shell-interpreted command string, since both an SSID (whatever a nearby access point broadcasts - real untrusted input) and a WiFi password (typed by whoever is at the device) are genuinely attacker-influenceable, and this avoids the entire shell-metacharacter-injection question by construction rather than by careful escaping.

Real decisions, per `Field WiFi and Network Resilience Concepts.md`:
- **Entry point**: Ctrl+W, a second discoverable keybinding alongside Ctrl+L - doubles as "cancel" from within the flow. Deliberately excluded from `UI_MODE_LOCKED` and the PIN-setup modes (same "don't jump modes mid-flow" reasoning applied to both keybindings now).
- **Session impact**: no special graceful teardown of an active session before switching networks - changing networks fundamentally requires dropping the interface, and `client.c`'s existing tested reconnect-with-backoff loop (Week 3 Day 2) already picks this up cleanly, with `PROTOCOL.md`'s per-session `seq_num` reset requiring no changes. Chose not to add a bespoke teardown path for a rare, user-initiated operation.
- **Flow**: scan → numbered list (reusing `input_buf`, unmasked, since a list index isn't sensitive) → password entry for secured networks (reusing the same masked buffer as PIN entry, since `ui_mode` makes the two mutually exclusive) → connect → explicit success/failure reported to history, with `nmcli`'s own specific error text on failure rather than a generic message.
- **Never blocking the UI thread**: `wifi_scan()`/`wifi_connect()` are real, multi-second network operations - both run through a "pending action" mechanism that defers the actual call until *after* `ui_mutex` is released, the same "never hold the lock across something slow" discipline as `session.c`'s `send_mutex` and this file's own earlier `ui_mutex`-starvation fix. Honestly documented tradeoff: since this runs synchronously within the same `ui_poll_line()` call rather than on its own thread, the scan/connect duration does delay that call's return to its caller (the sender loop or the idle thread) - acceptable for a rare, deliberate action, unlike the routine per-slice polling the earlier fix addressed.
- **"No network found"**: the idle-input thread (see the idle-input-thread entry above) now also runs `wifi_has_connectivity()` every 15 seconds and sets the status bar to "No network found - press Ctrl+W to set up WiFi." when there's none - deliberately coarser than the 200ms input-poll granularity (a real subprocess spawn each time), and only ever *writes* the status bar when disconnected, so it doesn't fight `client.c`'s/`server.c`'s own more specific status updates for ownership of that line except for a possible brief cosmetic flicker right at a state transition.

### Verified on real hardware (alpha), deliberately scoped around the risk to my own SSH access
`wifi_scan()`/`wifi_has_connectivity()` are read-only and were tested directly first, safely: found the real network (`BDH-public`) already known from Day 1, connectivity check accurate.

`wifi_connect()`'s failure path was verified in isolation, safely, using a **nonexistent SSID** rather than a wrong password on a real network - `nmcli` fails at lookup ("Error: Parameter '...' is neither SSID nor BSSID") before ever touching the active connection, so this carried no risk to the SSH session being used to test it, and it did survive intact (confirmed via `nmcli general status` immediately after).

The full UI flow was then verified live, stopping deliberately short of an actual submit against the real network (to avoid the real risk that a wrong password or a network change could drop the very SSH session running the test):
1. Ctrl+W with **no connection active at all** (idle-thread path) → scan ran and rendered a real, numbered list of 10 nearby networks correctly.
2. Selected network 1 (`BDH-public`) → correctly prompted for its password.
3. Typed a test password → correctly masked (6 characters shown as 6 asterisks).
4. Cancelled via Ctrl+W rather than submitting → cleanly returned to normal mode, no connection attempt made, SSH session and existing WiFi connection unaffected.
5. Re-entered, selected an out-of-range network number (99) → correctly showed "Invalid selection - try again" and stayed in selection mode.

**Not yet done**: an actual successful connect to a genuinely new network, per the walkthrough's own explicit requirement. Deliberately left for the user to do physically at the device (pressing Ctrl+W and joining, e.g., a phone hotspot themselves) rather than risking remote SSH access over it - the safer and, for this specific screen, more authentic test of the real field-use scenario anyway.

## Touch input — "Selection + wake" — 2026-08-21

Real physical keyboards turned out not to be attached to either Pi yet (ordered, not yet arrived). The user wanted touch to be a real part of the finalized UI regardless, scoped explicitly: keyboards remain the only way to *type* (no on-screen keyboard - a genuinely separate, much larger feature, deliberately not built); touch adds three selection/gesture actions on top of what already exists.

### Hardware, confirmed rather than assumed
`cat /proc/bus/input/devices` identified the touch controller: an `ft5x06` capacitive touch chip at `/dev/input/event1` (I2C). `evtest` confirmed its exact capabilities: `ABS_X` 0-799, `ABS_Y` 0-479 (800x480 physical resolution), `BTN_TOUCH`, full multitouch protocol support, and `INPUT_PROP_DIRECT` (a direct-touch device, coordinates map straight to screen position, no separate pointer/cursor semantics). New `include/touch.h`/`src/touch.c`: enumerates `/dev/input/event*` and matches by **capability** (`ABS_X`+`ABS_Y`+`INPUT_PROP_DIRECT`), never a hardcoded device path - the exact event number is not guaranteed stable, the same lesson already learned from the DSI/HDMI `fb0`/`fb1` surprise below.

### Three gestures, in `ui.c`
- **Locked**: a tap clears any lingering "Wrong PIN" message and redraws a clean prompt - the closest honest analog to `ncurses UI Concepts.md`'s own suggested "wake/dismiss a screensaver-equivalent", since this project has no actual screen-dimming feature to wake from.
- **`UI_MODE_WIFI_SELECT`**: tapping a rendered network entry selects it, equivalent to typing its number and pressing Enter. The row a given entry occupies is remembered at render time (`wifi_list_header_row`) - a known, documented edge case: an incoming chat message scrolling `history_win` further while the list is showing would make this mapping stale, since the receiver thread's `ui_add_history()` calls never pause for UI mode.
- **`UI_MODE_NORMAL`**: tapping the upper half of `history_win`'s rows "pauses" it (stops `wrefresh()`-ing on new content, reusing the exact suppress-refresh technique the lock screen already uses); tapping the lower half "resumes" (reveals everything that accumulated via `touchwin()`+`wrefresh()`). Deliberately **not** true arbitrary scrollback, which would need converting `history_win` from a plain window to a pad - a real architecture change. "Pause so new messages don't push away what you're reading, then catch up" covers the actual motivation without that rewrite; documented as the honest, chosen scope rather than literal scrolling.

Threading: the touch thread does **not** need `ui_start_idle_input()`/`ui_stop_idle_input()`-style bracketing around sessions - it never touches `input_win`'s own `wgetch()` read state, only `ui_mutex` to update shared UI state, exactly like the receiver thread's `ui_add_history()` calls already do. Runs for the whole process lifetime, started once in `ui_init()`.

### Verified on real hardware - a real testing-infrastructure problem found and fixed along the way
The raw touch-reading layer was proven first, in isolation: a throwaway test program correctly caught a real physical tap (`x=0.269 y=0.852`, sensible normalized coordinates) on the very first real attempt.

Testing the full tap-to-UI-action path surfaced a genuine gap in the test methodology itself: everything tested via `tmux` up to this point runs in a virtual pty, invisible on the physical touchscreen (which shows `tty1`, the real console) - a tap on the physical screen has no relationship to what's rendered in a `tmux` session. Running the actual binary on the real console (`tty1`) hit two real, separate problems, each root-caused rather than worked around blindly:
1. **`TERM=dumb`** - an SSH session's inherited environment isn't a real terminal type; `openvt`'s child process inherited it, and ncurses couldn't use it properly. Fixed by explicitly setting `TERM=linux` (the correct terminfo for a raw Linux console) when launching.
2. **The DSI console-binding issue (see below) had resurfaced** after the user's reboot, on both units - confirming directly (not just inferred) that the `fb0`/`fb1` assignment really is non-deterministic across boots, not just differing between the two physical units: `bravo`'s own assignment was the *opposite* of what it was earlier this same session.

With both fixed, `sudo TERM=linux openvt -f -w -c 1 -- ./build/server ...` ran the real server on `alpha`'s actual physical console, confirmed showing "Listening on port 4433..." Connected `bravo` as a client and ran the pause/resume gesture for real: an upper-half tap correctly paused history (confirmed via temporary debug logging: `history_paused` 0→1), a message sent from `bravo` while paused did not appear, and a lower-half tap correctly resumed and revealed it (`history_paused` 1→0, user confirmed the message appeared) - the complete gesture, cross-verified between the user's visual confirmation and the debug log, not just one or the other.

### Follow-up, same day: the remaining two gestures tested too, via synthetic keyboard input

The lock-screen and WiFi-select gestures both need keyboard input (Ctrl+L / Ctrl+W) to even reach their state first, and no physical keyboard is attached yet. Rather than leave them untested, built a small ad-hoc tool using the raw Linux `uinput` ioctl interface directly (the same category of API `touch.c` already uses for reading, applied here to *writing*): creates a temporary virtual keyboard device, injects a Ctrl+L or Ctrl+W keypress, then destroys the device. Confirmed it works exactly like a real keyboard as far as the kernel's console input layer is concerned - the running server responded to it identically to a real keypress.

**WiFi-list tap-select confirmed working on real hardware**: injected Ctrl+W → real scan rendered a real network list on the physical screen → the user physically tapped a specific entry → correctly transitioned to that network's password prompt. The user's own feedback while testing this - "the text is so small, choosing 1 in particular is hard" - is a real, concrete usability finding, not a defect in the gesture logic itself; noted as direct motivation for the "GUI-like final iteration" direction discussed the same day.

**Lock-screen tap gesture confirmed working**, via a different approach: rather than inject a full typed PIN (the synthetic-keyboard tool only sends single Ctrl+key combinations), seeded a PIN directly with a small program calling `lock_set_pin()` - bypassing UI text entry entirely to reach the locked state, then a real physical tap confirmed the screen stayed locked and responsive with no crash.

**A real test-methodology bug found and fixed along the way**: the seeded PIN wasn't found on the first attempt after seeding - not a bug in `lock.c`, but in the test setup: the seeding tool ran as `connor` (writing to `/home/connor/.securelink/pin_hash`), but the server was launched via `sudo openvt`, and `sudo` resets `HOME` to `/root` by default - so the server (running as root) correctly found no PIN at `/root/.securelink/pin_hash` and started unlocked. Fixed by using `sudo --preserve-env=HOME env TERM=linux openvt ...` (preserving `HOME` specifically while still forcing the correct `TERM`) rather than assuming `sudo`'s environment handling would just work. Worth remembering for any future testing that mixes `sudo` with per-user state files.

### A real information-disclosure bug found via this same physical-console testing, fixed the same day
While checking the lock screen on the real console, the user noticed the server's startup banner - printed before `ui_init()` takes over, since it can fail before there's any UI to report errors through - included the **full filesystem paths** to the certificate, private key, CA, and revocation-list files (e.g. `wolfSSL initialized; cert/key/CA loaded from /home/connor/pki/server_cert.pem / ...`). Confirmed genuinely visible on the physical touchscreen, not just a development-time convenience - and since Day 5's systemd service will need this exact same startup-then-ncurses-takes-over sequence to render on the real console, this wasn't just a testing artifact, it would have shipped. A device meant to sit somewhere semi-public shouldn't hand a casual observer the exact on-disk layout of its own private key material.

**Fixed in both `client.c` and `server.c`**: every pre-`ui_init()` `printf`/`fprintf` that included a path argument (the success-path "loaded" messages, and the `wolfSSL_CTX_use_certificate_file`/`_use_PrivateKey_file`/`_load_verify_locations` failure messages) now reports success/failure generically (e.g. "check the -c path was given correctly") with zero path content. Verified directly: redirected the real binary's stdout to a file (ncurses itself fails on a non-tty target, which is fine - the goal was just to see the raw pre-init text) and confirmed the banner now reads "Loaded revoked-serials list." / "wolfSSL initialized; certificate, key, and CA loaded." with no paths anywhere. `print_usage()` was checked too and found already safe (only ever shows generic placeholder names like `<server_cert.pem>`, never a real path).

### The DSI console-binding fix, made persistent
The `con2fbmap` fix from earlier this session (see "Real hardware follow-up") was explicitly noted at the time as *not* persisting across reboots - and it bit us again, on both units, the very next reboot, confirming that note was correct rather than overcautious. Fixed properly this time: `docs/fix-console-fb.sh` + `docs/fix-console-fb.service`, a `systemd` oneshot service that identifies the DSI framebuffer by **name** (`drm-rp1-dsidrmf`), never a hardcoded index, and runs `con2fbmap` before `getty@tty1` starts. Installed and enabled on both Pis; verified by running the script directly (correctly bound console 1 to whichever index the DSI panel actually was on each unit) - **not yet re-verified via an actual reboot cycle**, left as a follow-up rather than putting the user through a third reboot in one session.

## Week 4, Days 2-3 — richer ncurses styling (aesthetic Phase 1) — 2026-08-21

The user gave an explicit two-phase direction for the finalized UI's look: start with richer use of ncurses' own real capabilities now; a more distinctive Flipper-Zero/Cyberpunk-2077-style aesthetic is a later, separate pass, not attempted here.

**Color palette confirmed against the real deployment target, not assumed**: checked `has_colors()`/`COLORS`/`COLOR_PAIRS` with `TERM=linux` on the actual Pi console - `COLORS=8`, `COLOR_PAIRS=64` (the standard ANSI 8-color palette, not 256-color/truecolor). Every color pair in `ui.c` stays within that, using `A_BOLD` for "bright" variants rather than anything that would silently fail on the real hardware this project targets.

**What changed in `ui.c`**:
- 7 color pairs: a filled cyan "title bar" look for the status line (`wbkgd()`), cyan borders, green for incoming (peer) messages, yellow for the user's own sent messages, cyan for system/event notices, red for the lock screen and any sensitive-entry mode (PIN/WiFi password), cyan for the normal input prompt.
- `history_win` and `input_win` were restructured from plain `newwin()`s into a border-window + inner-derwin() pair each (`history_border_win`/`history_win`, `input_border_win`/`input_win`) - the standard ncurses pattern for a border that survives scrolling, since a derwin() physically shares the same character grid as its parent's interior. Every existing call site (`ui_add_history()`, `redraw_input_locked()`, the WiFi list rendering, etc.) kept using the same `history_win`/`input_win` names for content; only what they're created *from* changed.
- The touch thread's row-math (`handle_tap_locked()`) needed a matching offset update, since `history_win`'s content now starts at absolute screen row 2 instead of row 1 (row 1 is now the border's top edge) and its height shrank by 2 (accounting for top+bottom border).

**Verified on real hardware, in stages**:
1. `tmux capture-pane` confirmed the structural layout (box-drawing characters, correct positioning) with no crash - `tmux` doesn't render the actual Unicode glyphs, just raw ACS codes, so this only proved structure, not appearance.
2. Ran the real binary on the physical console (`sudo TERM=linux openvt -f -w -c 1 -- ./build/server ...`, same technique as the touch-testing session) so the user could see the actual rendered colors and borders - confirmed good.
3. **Real usability feedback led to a font change**: the user asked for bigger text, referencing the "text too small to tap accurately" finding from the WiFi tap-select test. Iterated through the Linux console's `Lat15-Terminus` font family (`setfont`) in response to explicit user sizing requests ("scale up another 50%", "a little more", then "a little smaller, like 25%") - landed on **`Lat15-Terminus24x12`** (12px wide × 24px tall character cells) as the final size, chosen because it maps exactly to a 25% reduction in each dimension from the largest available size (`32x16`) tested along the way.
4. Made the font choice **persistent across reboots** via `/etc/default/console-setup`'s `FONTFACE="Terminus"`/`FONTSIZE="12x24"` (Raspberry Pi OS's standard mechanism, applied by `console-setup`/`setupcon` at boot) - set on both Pis, not just applied live via `setfont` for the current boot session, learning directly from the earlier `con2fbmap` persistence lesson rather than repeating that mistake with the font too. **Not yet re-verified via an actual reboot cycle** - same honest caveat as the console-fb fix above.
5. Deployed the styled `ui.c` to `bravo` (it had only ever been tested on `alpha` during the live-iteration session) and confirmed it compiles and links clean there too, zero warnings.

## Week 4 Day 4 — mutual key-share protection (no secure element) — 2026-08-22

Replaces the secure-element chip plan with a software-only scheme: each device's private key is AES-128-CTR encrypted at rest with a key `K` that is never itself stored, in reconstructible form, on the same device - `K` is split via XOR into `local_share` (stays on the device) and `remote_share` (held by the *paired* device as a custody-share), each information-theoretically worthless alone. See `docs/../04-Week 4 - Physical Build/Network-Fetched Key Protection Concepts.md` (vault) for the full design.

### New code
- **`tools/keyshare_setup.c`** - one-time dev-machine tool: generates `K`/`R` via a real CSPRNG on every platform (`/dev/urandom` on Linux, `rand_s()` on Windows - deliberately *not* the `rand()` fallback other, non-security-critical parts of this project use), encrypts a device's PEM private key, writes `<device>_key.enc`/`_share_local.bin`/`_share_remote.bin`.
- **`include/keyshare.h`/`src/keyshare.c`** - `keyshare_reconstruct()` (background share-listener bound to the local Tailscale IP only + a retrying fetch of this device's own share from its peer, both gated by `tailscale whois` identity verification since the SecureLink mTLS key can't authenticate the request that unlocks itself), `keyshare_decrypt_private_key()` (pure AES-128-CTR, deliberately kept portable/non-Linux-guarded so it could be unit-tested on the dev machine before ever touching Pi hardware).
- `client.c`/`server.c`: new `-K <dir> -P <peer_ip> -N <peer_hostname>` mode alongside the existing `-k <path>` plain-PEM mode (kept for dev-machine testing and devices without this protection set up).

### Bugs found and fixed via real testing, before ever touching Pi hardware
1. **`keyshare_decrypt_private_key()` was accidentally Linux-only** - it has zero platform-specific code (pure AES), but got caught inside the `#ifdef __linux__` split alongside the genuinely-Linux-only networking pieces. Found immediately by a dev-machine round-trip test (encrypt via the setup tool, decrypt via the library call, compare byte-for-byte against the original `server_key.pem`) returning -1 unconditionally. Fixed by moving it outside the platform split entirely - this is also what made the dev-machine round-trip test possible at all, catching real logic bugs before real hardware was ever involved.
2. **A missing-object-file build error masqueraded as a mysterious linker failure** (`collect2.exe: error: ld returned 5 exit status`, no further detail, inconsistent across retries via the Bash tool specifically). Isolated by running the identical link command through PowerShell instead, which surfaced the real message plainly: `hw_expansion.o`/`hw_oled.o`/`hw_tts.o` were simply missing from a from-scratch dev-machine `build/` directory. Not a real code bug - just files that had never been compiled on this specific machine in this session before.

### Verified on real hardware
- **Round-trip proof (dev machine, before deployment)**: generated real `K`/`R`/shares for both `alpha` and `bravo` from the actual production `server_key.pem`/`client_key.pem`, decrypted using the manually-XORed shares, confirmed byte-for-byte identical to the original PEM files.
- **Deployment**: each device's files correctly renamed on delivery (`key.enc`, `share_local.bin`, `peer_custody_share.bin` - the custody-share filename is deliberately generic, since it's *the peer's* share being held, not "this device's own" anything) - verified both directories directly via `ls` before ever running the binaries.
- **First live attempt hung** - both devices stuck indefinitely on "Fetching this device's key-share...". Traced to the Week 3 Tailscale ACL (`docs/tailscale-acl.json`), which only permitted `client → server:4433` - one direction, one port. The new key-share fetch needs port 4434 in *both* directions (each device is simultaneously a keyshare-client and keyshare-server to the other). Confirmed the diagnosis with a raw `nc` connection attempt (hung, not refused - the signature of a silent ACL/WireGuard-layer drop) before touching any code. Fixed by adding two new explicit ACL rules (one per direction) and having the user paste the updated policy into the Tailscale admin console; re-confirmed with the same raw `nc` test afterward (now a clean, fast "connection refused" - i.e., traffic reaches the destination, just nothing was listening yet at that exact moment).
- **A second, more fundamental real bug found on the very next attempt**: `bravo` connected and completed its own key reconstruction *first*, and the original code called `keyshare_stop_listener()` immediately afterward on the theory that a device's listener only needs to serve its peer once, near mutual startup. This stopped `bravo`'s listener before `alpha` had gotten a chance to fetch *its own* share from `bravo`, permanently deadlocking `alpha`. Confirmed directly via `ss -tlnp` showing `bravo`'s port 4434 genuinely closed. This wasn't just a race to patch around - it revealed the underlying assumption was wrong: the listener has to run for the **whole process lifetime**, since a peer might need to fetch its share at any later point, including after its own completely independent reboot, hours or days after this device's own startup. Fixed by removing the early-stop calls entirely; `keyshare.h`'s doc comment now records this reasoning explicitly so the mistake doesn't get reintroduced.
- **Full success after both fixes**: real, live two-Pi test - `alpha` (server) and `bravo` (client) each independently fetched their own share from the other over Tailscale, reconstructed `K`, decrypted their private key, loaded it into `WOLFSSL_CTX` via `wolfSSL_CTX_use_PrivateKey_buffer()`, and completed a genuine mTLS handshake with revocation checking - then exchanged real messages in both directions, verbatim confirmed on both screens.
- **The actual security property, proven, not just asserted**: took `bravo`'s own on-disk custody-share for `alpha` (exactly what an attacker who stole *only* `bravo`'s SD card would have) and tried decrypting `alpha`'s `key.enc` using that lone share as if it were the complete key `K_A`. Result: 1732 bytes of pure random-looking garbage, not a valid PEM header - directly confirming a single stolen device's files cannot reconstruct the *other* device's private key, exactly the requirement this whole design was built around.

### Not yet done
- The one-time setup tool's output has never been run through the Day 6 rotation drill yet (regenerate + redistribute a share pair for an already-deployed device) - deferred to Day 6 itself.

### Retry-with-backoff, tested as its own dedicated scenario — 2026-08-22

The earlier test above exercised retry incidentally (both devices happened to wait through real retry cycles before the ACL was fixed). This is a deliberate, isolated repeat, specifically to prove the "peer currently unreachable" boot path in isolation, not bundled with debugging something else.

**Setup**: `bravo`'s client started first (in `-K`/keyshare mode), with `alpha`'s server deliberately *not* running yet.

**Observed**: `bravo` printed its one-time "Fetching this device's key-share from its paired device over Tailscale (retrying until it's reachable)..." message and then genuinely blocked - confirmed via `ps` that the process was alive and idle, not crashed, roughly 12 seconds in (mid-way through the 1s→2s→4s→8s→16s→30s-capped backoff climb in `keyshare_reconstruct()`). No per-attempt log line is expected or printed between retries - that's by design, not a bug (see `src/keyshare.c`'s retry loop).

**Recovery**: `alpha`'s server was started roughly 13 seconds after `bravo`. `alpha` came up almost immediately, since `bravo`'s own share-listener had been running the whole time it was retrying (a device's listener starts before its own reconstruct loop begins, so a peer can always find it even mid-retry). `bravo`'s very next scheduled retry attempt then succeeded: `Key-share reconstructed.` appeared in its log, followed by a full mTLS handshake and `Connected to server` on screen.

**Full proof, not just "it unblocked"**: sent a real message from `bravo` (`retry-with-backoff test message`) after recovery and confirmed it displayed correctly on `alpha`'s screen (`client: retry-with-backoff test message`), with `alpha`'s verify callback log showing the same revocation check passing as every prior successful connection - proving this wasn't a degraded/partial recovery, the session is fully functional afterward.

This closes the "not yet done" gap from the first Day 4 test above - retry-with-backoff is now verified as its own scenario, independent of the ACL/listener-lifetime debugging it was previously entangled with.

### File permissions - folded into a real provisioning step — 2026-08-22

Previously done ad hoc (`chmod 600` typed by hand during live testing, per the entry above). Added `docs/provision-permissions.sh`: locks `~/pki` and `~/keyshare` to `700` (directory) and `600` (every regular file inside), idempotent, safe to re-run any time (e.g. after Day 6's rotation drill deploys a new certificate). Deployed and run on both `alpha` and `bravo`; verified via `ls -la` on both that every file/directory landed at the intended mode. Skips gracefully (prints a note, doesn't error) if a device only uses one of the two directories.

**Not yet done**: Phase 2 (the distinctive Flipper Zero/Cyberpunk 2077-style aesthetic) - deliberately deferred, per the user's own two-phase framing. An actual reboot-cycle re-verification of the font persistence, same as the still-open `con2fbmap` one.

## Week 4 Day 5 — overlay filesystem, persistence, systemd service — 2026-08-22

Genuinely the highest-risk day of the whole project so far: enabling a root overlay filesystem on live, already-provisioned hardware, and installing a systemd unit that takes over the physical console. Three real, serious bugs were found - one of them caused an extended (~20+ minute) outage on both devices simultaneously, requiring a physical power cycle and the user directly typing diagnostic commands on the console. Documenting the full sequence, not a cleaned-up version, since the debugging path here is itself the valuable part.

### Design: persistence via a real filesystem outside the overlay, not overlay exclusions

Checked `overlayroot`'s actual config/manpage directly on-device (not assumed): it has no per-directory exclusion option. `recurse=0` is the real mechanism - it keeps *every other mounted filesystem* real and writable, only `/` itself becomes the RAM-backed overlay. Design: a 96MB ext4 image (`/boot/firmware/persist.img`) stored on the boot partition (a genuinely separate partition, never touched by the root overlay regardless of `recurse`), loop-mounted at `/persist`, with the five paths that need to survive a reboot bind-mounted from it:

- `/var/lib/tailscale` - node auth state (Tailscale key expiry is already disabled, but the state itself still needs to survive or it re-auths from scratch every boot)
- `$HOME/.securelink` - PIN salt+hash
- `/etc/NetworkManager/system-connections` - WiFi profiles joined later via the Days 2-3 UI
- `$HOME/pki` - cert/key, **and** `revoked_serials.txt` (deliberately relocated here from `~/securelink/`, so a cert rotation's revocation-list update persists too)
- `$HOME/keyshare` - the keyshare-mode encrypted key + shares

New scripts: `docs/setup-persist-overlay.sh` (idempotent - creates the image, migrates existing real content in on first run, adds the fstab entries) and `docs/enable-overlay.sh` (the actual `overlayroot=tmpfs:recurse=0` cmdline edit, kept as a separate, deliberate step).

### Verified in the safe order: persistence first, alone, before overlay

Ran `setup-persist-overlay.sh` on both, rebooted both (with overlay still off - a `nofail` bind-mount failing would just degrade gracefully to the original non-persisted directory, never block boot). Confirmed on both: all 5 bind mounts active (`mount | grep persist`), all files intact, Tailscale reconnected without re-auth, zero failed units. This is the same "prove the plumbing before adding the risky part" discipline used throughout this project.

### Overlay enabled, proven with a real experiment, not just documentation

On `alpha`: wrote a marker file into a persisted path (`~/pki/overlay_test_marker.txt`) *and* a non-persisted path (`~/overlay_ephemeral_test.txt`) before the overlay-enable reboot, to prove both halves of the claim - persisted paths survive, everything else genuinely doesn't. First attempt's "ephemeral" result was a methodology bug on my part (the file was written *before* overlay activated, so it was already baked into the frozen lower layer - not a real ephemeral-write test at all). Corrected: wrote the marker *while overlay was already active*, rebooted again, confirmed it was genuinely gone (`No such file or directory`) while the persisted marker survived. Same two-part test repeated and passed cleanly on `bravo`.

### Real bug 1 - masking `systemd-remount-fs.service` globally broke root-writability on non-overlay boots

`systemd-remount-fs.service` (which transitions root from its initial state to the full read-write state fstab specifies) fails on every overlay-active boot with `fsconfig() failed: overlay: No changes allowed in reconfigure` - cosmetic (root is already correctly read-write via the overlay's own tmpfs upper layer) but costs ~20-25s of retry/backoff at boot. Masked it to fix that - but masked it **globally**, not conditionally on overlay actually being active. Consequence, discovered directly (`mount | grep ' / '` showing `ro`, `sed: couldn't open temporary file: Read-only file system` when trying to edit `/etc/fstab`): on a later **non-overlay** boot (done deliberately, to install the systemd unit persistently), root got stuck permanently read-only, since the one service responsible for the real read-write remount was disabled. Fixed with `mount -o remount,rw /` (bypasses the masked service directly) to recover immediately, then `systemctl unmask systemd-remount-fs.service` on both devices to properly revert the over-broad fix. **Decision**: accept the cosmetic ~20s overlay-boot delay rather than mask this service again - the risk of quietly breaking non-overlay maintenance boots isn't worth the cosmetic win, especially having just been burned by it directly.

### Real bug 2 - a boot-ordering race crashed NetworkManager, causing an extended real outage on both devices

The most serious incident of the day. After installing the systemd service files and disabling `getty@tty1` on both, rebooted both together (needed anyway, since `alpha` blocks on fetching its key-share from `bravo`). **Both devices went unreachable** - not via mDNS, not via raw Tailscale IP, not via ICMP ping - for over 20 minutes. Diagnosed step by step, entirely through the user's own eyes and typed commands, since I had zero remote access:

1. User confirmed both were genuinely booted (shell prompt visible, auto-login worked) - ruled out a boot failure.
2. `hostname -I` on-device showed `127.0.1.1` (the Debian `/etc/hosts` self-referencing loopback fallback, not a real DHCP lease) - confirmed this was specifically a networking failure, not a boot failure.
3. A full physical power cycle (not just a soft reboot) did **not** fix it - ruled out a transient/stuck-state issue.
4. `journalctl -u NetworkManager -b` (typed and pasted by the user, since I had no other way to see it) showed the real cause: NetworkManager crashing repeatedly (`Main process exited, code=killed`, `Start request repeated too quickly` - systemd's own restart-storm protection giving up after 5 failures in quick succession).

**Root cause**: the `/etc/NetworkManager/system-connections` bind mount had no explicit ordering relative to `NetworkManager.service`. `NetworkManager.service` starts very early in boot (often before `local-fs.target`'s own mounts, including `/persist`, are guaranteed complete) - the bind mount could race NetworkManager's own startup, most plausibly corrupting its inotify-based directory watch on that path mid-initialization. **Confirmed empirically**: `sudo umount /etc/NetworkManager/system-connections` (live, no reboot) + `systemctl restart NetworkManager` immediately restored connectivity on `bravo`; the same live fix restored `alpha`.

**Permanent fix**: added explicit systemd ordering directly on the fstab bind-mount line - `x-systemd.requires-mounts-for=/persist,x-systemd.before=NetworkManager.service` - forcing the bind mount to fully complete before NetworkManager is even allowed to start, closing the race by construction rather than by luck. Verified via two full, isolated reboots (`alpha` alone first, then `bravo`): root correctly read-write, NetworkManager active with `wlan0` connected on the very first attempt each time, zero failed units, Tailscale reconnected cleanly.

### Real bug 3 - `After=cloud-init.target` created a genuine systemd dependency cycle, silently deleting the service's own start job every boot

Separately (after the NetworkManager fix), noticed the console displayed our app's own early output interleaved with *later* cloud-init boot messages, visually corrupting the screen (confirmed by reading `/dev/vcs1` directly - the real virtual-console text buffer - rather than relying on descriptions of what the physical screen showed). Added `After=cloud-init.target` to fix the interleaving. Result: the service **never started at boot at all** - `systemctl status` showed `inactive (dead)`, zero journal entries, yet manually running `systemctl start securelink-alpha.service` worked perfectly (proving the unit itself was fine). Root cause, found directly in the journal: `multi-user.target: Found ordering cycle on securelink-alpha.service/start` / `Job securelink-alpha.service/start deleted to break ordering cycle` - `cloud-init.target`'s own chain has a `Before=multi-user.target` relationship that, combined with this unit's own `WantedBy=multi-user.target`, closed a genuine cycle. Systemd's cycle-breaker resolves this by silently deleting the job, with no error surfaced anywhere obvious - which is exactly why it looked like "nothing is wrong" while nothing was actually running. Adding `Wants=cloud-init.target` alongside `After=` did not resolve the cycle either (same silent failure). **Decision**: dropped the `cloud-init.target` ordering entirely. Reliable auto-start matters far more than a few seconds of cosmetic console text-bleed, which ncurses' own periodic redraws self-heal anyway once real content updates arrive.

### Full verification after all three fixes - genuine cold-boot-to-connected proof

Rebooted both together. Both `securelink-alpha.service`/`securelink-bravo.service` came up `active (running)` automatically, zero failed units, no cycle warning in the journal. Read `/dev/vcs1` directly on both (not relying on a description of the physical screen) - both showed a fully completed, correct session with **zero manual intervention of any kind**:

```
alpha: Connected to client
       Verify callback: checking serial 68A7E95F... against revocation list.
       Verify callback: serial 68A7E95F... not revoked, proceeding.

bravo: Connected to server
       connect() failed: 111   [x2 - expected: alpha's server wasn't
                                 listening yet in bravo's first two
                                 reconnect attempts; bravo's own
                                 reconnect-with-backoff correctly
                                 recovered]
```

Sent a real message from `bravo` using an ad-hoc `uinput`-based synthetic-keyboard test tool (no physical keyboard attached yet) and confirmed it displayed correctly on `alpha`'s real console (`client: ...`) - the exact text was garbled due to a timing bug in the throwaway test tool itself (key-tap speed, not a real app bug), but the end-to-end delivery proof stands regardless. This is the actual Day 6 "cold power-on, zero manual steps, both connect automatically" milestone, achieved a day early as a direct result of getting the systemd service correctly installed.

### Crash recovery, tested for real

`kill -9` on the running `server` process's PID on `alpha` while it was live-connected. Confirmed via `systemctl status`: a fresh process (new PID) was `active (running)` again within ~1 second (`RestartSec=5` gave headroom, actual recovery was faster). Confirmed via `/dev/vcs1` that the fresh process genuinely re-ran its full startup sequence (re-fetched its key-share, re-completed the mTLS handshake, reached the same healthy `Connected to client` state) rather than just restarting into a stuck state - this was the actual crash-recovery scenario the Day 5 checklist calls for, not just "the process exists again."

### Systemd unit design decisions

`docs/securelink-alpha.service` / `docs/securelink-bravo.service`: `User=connor`/`Group=connor` (not root), `TTYPath=/dev/tty1` with `TTYReset=yes`/`TTYVHangup=yes`/`TTYVTDisallocate=yes` (ncurses needs to own the terminal exclusively, which is why `getty@tty1` had to be disabled *and masked*, not just stopped), `Restart=always`/`RestartSec=5` (field-deployed, unattended - a crash shouldn't leave a dead screen until someone physically power-cycles it, but a 5s floor avoids hammering the log/CPU if something's systematically broken). **Clock-sync-before-cert-validation decision**: deliberately *not* gated via `After=time-sync.target` - checked directly on-device that `time-sync.target` is never actually reached unless `systemd-time-wait-sync.service` is separately enabled (disabled by default on this image, and enabling it would add a real, possibly lengthy boot-time NTP wait, working against "zero manual steps, fast to a usable session"). Relying instead on `client.c`'s existing reconnect-with-backoff loop, which already retries any handshake failure including the specific clock-skew failure mode (`ASN date error, current date is after expiration` - the exact string seen in Week 2 Day 5's expired-cert negative test) - the system self-heals past a wrong-clock boot via normal retry once NTP catches up, with zero extra boot-ordering machinery (and zero risk of another ordering-cycle surprise like bug 3 above).

### Not yet done
- Overlay-filesystem persistence has not yet been tested through a Day 6 certificate-rotation drill (deploying a new cert while overlay is active, confirming it survives a reboot) - that's explicitly Day 6's own task.
- The mobility drill (moving a device to a different network mid-session) hasn't been run since enabling overlay/persistence - worth re-confirming the WiFi-profile persistence path specifically, given how much churn today's NetworkManager incident involved.

## Messaging system enhancements — 2026-08-22

The user asked directly what would make this a better messaging system, and after a joint prioritization (explicitly excluding message editing/deletion and multi-device/group messaging as poor fits for this project's security posture and two-device architecture), asked for everything else: timestamps, offline message queueing, delivery acknowledgment, persisted message history, real scrollback, small file transfer, and a live link-quality (RTT) indicator. Built in that order (lowest-risk first), tested incrementally, with real scrollback deliberately saved for last as its own dedicated pass given how much working code it touches.

### Protocol additions (docs/PROTOCOL.md)
Two new `msg_type` values, both added to `message.h`'s enum AND `message.c`'s parse-time whitelist switch (confirmed by checking the actual code, not assumed - the switch would have silently rejected them otherwise):
- `0x05 ACK` - 4-byte body, the big-endian `seq_num` of the `TEXT_MESSAGE` being acknowledged. Sent automatically by the receiver the moment a `TEXT_MESSAGE` is accepted.
- `0x06 FILE` - `[2-byte filename_len BE][filename][file data]`, still bound by the existing 65536-byte `body_length` cap (no chunking/reassembly - a file that doesn't fit is rejected by the sender before anything is transmitted). Receiver treats the filename as untrusted wire input: basename-only, path separators stripped, `.`/`..` rejected outright (see `sanitize_basename()` in `session.c`).

`tests/test_message.c` (unchanged) still passes 5/5 after these additions - confirmed by rebuilding and rerunning on real hardware, not assumed safe because "only new cases were added."

### New modules
- **`outbox.h`/`outbox.c`** - a small, bounded (20 messages), thread-safe FIFO queue. Cross-platform, no `__linux__` split needed (pure in-memory, pthread already proven working on both this project's real targets). Verified in isolation first (a throwaway dev-machine round-trip test: enqueue/dequeue/count/full/empty), same discipline as every other module this project has built.
- **`msglog.h`/`msglog.c`** - append-only, timestamped, local chat log at `$HOME/.securelink/message_log.txt` - deliberately the SAME directory the PIN hash already uses, so it's automatically covered by the existing Day 5 overlay-persistence bind mount with zero changes needed to `docs/setup-persist-overlay.sh`. **Honest, stated limitation**: stored in plaintext, protected only by file permissions and the device's own physical/OS security - real encryption-at-rest would need its own key-management story (the mutual key-share mechanism's key is per-session/ephemeral, unsuitable for something meant to persist across many sessions) - not attempted, documented instead, matching this project's Documentation Standard. Verified in isolation (append + load-recent round-trip) before integration.

### Feature-by-feature, what's real and verified
- **Timestamps** (`ui_add_history()`) - local wall-clock time only, `[HH:MM:SS]`, deliberately NOT carried on the wire (Raspberry Pis have no hardware RTC and clocks aren't guaranteed synchronized - a wire timestamp could be actively misleading across devices; same reasoning already applied to RTT below). Confirmed rendering correctly on real hardware.
- **Delivery ACK** - confirmed with a real, live round trip on real hardware: sent a message from `bravo`, `alpha` auto-ACK'd it, `bravo` displayed `(delivered: "...")` within the same second. Verbatim:
  ```
  [19:13:25] you: ngbn gbbajg z\g
  [19:13:25] (delivered: "ngbn gbbajg z\g")
  ```
  (garbled text is the same known synthetic-keyboard test-tool timing artifact documented earlier this project - the ACK mechanism itself doesn't care what the text says.)
- **Offline queueing** - the single most valuable addition, per the user's own stated goal ("a live chat pipe" vs. "an actual messaging system"). Tested for real: stopped `alpha`'s systemd service mid-session, typed a message on `bravo` while genuinely disconnected, confirmed the idle-input thread queued it (`outbox_enqueue()`) rather than dropping it, restarted `alpha`, confirmed `bravo`'s reconnect automatically drained and sent the queued message, confirmed `alpha` received it, confirmed the delivery ACK fired for it too. Full verbatim sequence on `bravo`:
  ```
  [19:16:06] Connection to server lost.
  [19:16:07] connect() failed: 111
  [19:16:10] (not connected - message queued, will send once connected)
  [19:16:37] you: queued message while offline
  [19:16:37] (delivered: "queued message while offline")
  ```
  A send that fails *mid-session* (not just while fully disconnected) is also queued rather than lost, per the same logic in `run_symmetric_session()`'s main loop - not separately live-tested this session (harder to trigger deliberately without corrupting the connection in a controlled way), but it reuses the exact same `outbox_enqueue()` call already proven above.
- **Persisted message history** - confirmed two ways: (1) `msglog.txt`'s content matched exactly what was sent/received during testing; (2) a real service restart replayed it correctly on boot:
  ```
  --- previous session history ---
  [2026-08-22 19:17:58] client: (sent a file - see ~/.securelink/received/)
  --- end of previous history ---
  ```
- **File transfer** - confirmed end to end, including a real bug found and fixed along the way (see below): `bravo` sent `/tmp/testfile.txt` via `/send /tmp/testfile.txt`, `alpha` saved it to `~/.securelink/received/testfile.txt` with byte-for-byte correct content (`test attachment content`, 24 bytes, matching exactly).
- **RTT / link-quality indicator** - implemented (periodic `PING` every `SESSION_PING_INTERVAL_SECONDS` (10s) while a session is active, RTT computed from the matching `PONG`, reported to the OLED's line 6 via `ui_report_rtt()`) and confirmed to compile/link/run without error, but **not yet visually confirmed on the physical OLED** - unlike everything else in this section, this one still needs the user to physically look at the display. Flagged honestly rather than claimed as proven.

### Real bug found and fixed: `~/.securelink` was root-owned
File transfer's first test attempt failed silently on the receiving end (`(failed to save received file testfile.txt)` in history; msglog had also been silently failing the same way, unnoticed until this pass since nothing had needed to *write* there yet). Root-caused, not guessed at: `ls -la ~/.securelink` showed `drwxr-xr-x root root` on both Pis - a leftover from an **earlier debugging session that ran the app via `sudo openvt`** (see the Days 2-3 touch-input testing narrative above), which created the directory as root before the real `User=connor` systemd service ever got a chance to. Once root-owned, `connor` could read/list it but never write into it - not a permissions-bits problem alone, a genuine ownership problem, silently degrading two brand-new features to no-ops. Fixed with `chown -R connor:connor ~/.securelink` on both devices, then **folded into `docs/provision-permissions.sh` permanently** (now covers `~/.securelink` alongside `~/pki`/`~/keyshare`, with explicit `chown` - not just `chmod` - specifically because a permissions-only fix would not have caught this class of bug). Re-ran the script on both Pis, re-verified file transfer and msglog both work correctly afterward.

### Full regression check after all of the above
`test_revocation`, `test_sha256`, `test_aes128`, `test_hmac`, `test_message` - rebuilt and re-run natively on `alpha` after all of today's changes: **5/5 pass, zero regressions**. Both services confirmed `active` with zero failed systemd units after the final restart.

### Not yet done
- **Real scrollback** (converting `history_win` from a plain window to an `ncurses` pad, replacing the pause/resume gesture with genuine bidirectional scroll) - deliberately saved for last as its own dedicated, more invasive pass, not started yet.
- RTT/OLED visual confirmation (see above) - needs the user's eyes on the physical device.
- The dev-machine loopback test harness hit a real, still-unexplained quirk this session: a backgrounded `server.exe`'s stdin (via a `<>`-opened FIFO, a technique that worked reliably for the *client* side reading from a plain redirected file) appeared to report ready-with-immediate-EOF, causing the server side to self-quit almost instantly in every attempt. Worked around by moving the authoritative test to real Pi hardware (which has no such issue - real systemd services, real TTYs) rather than root-causing a dev-machine-only harness artifact under time pressure. Worth investigating if dev-machine server-side interactive testing is needed again.
- Cold-boot-to-ready timing hasn't been formally measured/recorded yet (Day 6 asks for this explicitly).

## Touch gesture re-verification, a real UI bug fix, and a testing-tool root cause — 2026-08-22

Given how much of `ui.c` had changed since the three touch gestures (Days 2-3, "Selection + wake" scope) were last confirmed working, the user asked to re-verify them properly before starting on a new touch-keyboard feature, rather than assume they still worked.

### Real bug found in this project's own synthetic-keyboard TEST TOOLING - explains months^H^H^Hall of today's "garbled text"
Debug-instrumented `ui_poll_line()` to see the actual `ch` value ncurses received for a synthetic Ctrl+L keypress: got `ch=0` (NUL), not the expected `12` (ASCII form-feed / Ctrl+L). Root cause, found by inspection, not guessed: every ad-hoc synthetic-keyboard test tool built this session computed a letter's Linux keycode via `KEY_A + (letter - 'A')` - **that's wrong**. Linux's keycode table is laid out by physical keyboard ROW, not alphabetically - `KEY_P` (25) is immediately followed by a jump to `KEY_A` (30), and `KEY_L` (38) is followed by a jump to `KEY_Z` (44). The arithmetic version silently computed a real, but WRONG, key for most letters - which is the actual, now-confirmed root cause of every "garbled test message" observed and shrugged off as a "known timing artifact" throughout this entire project's synthetic-keyboard testing (never an application bug - genuinely confirmed here, not just re-asserted). Fixed with an explicit 26-entry lookup table in the (throwaway, deleted after use) test tool. Retested: `ch=12`, exactly correct.

### All three touch gestures re-confirmed working on real hardware, live, with the user physically tapping
- **Lock-screen wake/dismiss**: locked the screen, forced a real "Wrong PIN" error state, had the user tap - confirmed it cleared back to a clean prompt.
- **WiFi-list tap-select**: real scan (found `BDH-public`), had the user tap the listed entry - confirmed it correctly transitioned to the password prompt. (Debug-logged the actual tap coordinates for this one: the physical touch controller reported two touch-down events for one tap - a normal touchscreen-hardware characteristic, not a bug - the first landed one row past the list and was correctly ignored as out-of-range, the second landed correctly and selected the entry.)
- **History pause/resume**: sent a message from `bravo`, had the user tap the upper half of `alpha`'s history to pause, sent a second message (confirmed genuinely held back - screen unchanged), had the user tap the lower half to resume - confirmed both messages appeared together, in order, with the input line back to normal.

### Real UI bug found and fixed: lock banner's missing trailing newline
While re-testing the WiFi gesture, found the WiFi-scan-results text visually concatenated onto the tail of the lock screen's own "...press Enter to unlock." line with no line break between them (`unlock.WiFi networks found...`), and the "LOCKED" banner box remained visible underneath. Root cause: `draw_locked_overlay_locked()`'s final `mvwprintw()` call had no trailing `\n`, leaving `history_win`'s internal cursor sitting mid-line; the WiFi-scan-results code (the only other direct `wprintw()` consumer of `history_win` besides `ui_add_history()`, which always ends its own lines) appended directly onto whatever the cursor position already was. Fixed with a trailing `\n`. Verified: re-ran the exact same sequence, the WiFi list now starts cleanly on its own line.

**Known, deliberately deferred, related issue** (not fixed this pass): `draw_locked_overlay_locked()` calls `werase(history_win)` before drawing the LOCKED banner - this clears the window's ENTIRE internal buffer, not just the visible screen, meaning every lock cycle permanently discards whatever scrollback (including the boot-time persisted-history replay) was there before. Nothing is lost from disk (`msglog.txt` is untouched), but the *live, in-memory* scrollback view is reset on every lock. This has existed since the original Day 2-3 lock-screen implementation, not introduced today - it just matters more now that there's real persisted, replayable history to lose from view. Deliberately not patched as a standalone fix: the upcoming real-scrollback (pad-based) rewrite will need to redesign how the lock overlay and the scrollback content coexist anyway (an `werase()`-based "replace everything with a banner" model is fundamentally incompatible with a pad-based scrollback), so fixing this now would be throwaway work ahead of that larger, already-planned change.

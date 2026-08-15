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

*Not yet started.*

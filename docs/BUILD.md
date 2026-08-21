# BUILD.md — wolfSSL Build Instructions

Exact steps to build wolfSSL from source for this project, on Windows via MSYS2. Written Week 2, Day 1.

---

## Environment

Development happens on Windows, using the MSYS2 toolchain set up in Week 1 (`C:\msys64`). wolfSSL's build system is **autotools** (`autogen.sh` → `configure` → `make`), which requires a POSIX-like shell — this must be run from an **MSYS2 shell with the UCRT64 environment active**, not raw PowerShell/cmd, and not the plain/base MSYS shell either.

### Why UCRT64 specifically

MSYS2 has multiple parallel environments (MSYS/UCRT64/CLANG64/MINGW64), each producing binaries linked against a different runtime. All of Week 1's `securelink` code was built with the UCRT64 `gcc`. Building wolfSSL under a different environment (e.g. plain MSYS) would produce a library linked against a different runtime (`msys-2.0.dll`), which won't link cleanly against the rest of this project. wolfSSL must be built under UCRT64 to match.

### Getting the UCRT64 environment active in a scripted/non-interactive shell

Launching the "MSYS2 UCRT64" terminal from the Start Menu sets this up automatically. For a non-interactive invocation (e.g. `bash.exe -lc "..."`), set it explicitly first:

```bash
export MSYSTEM=UCRT64
source /etc/profile
```

Without this, `gcc`/`cc`/`clang` all resolve to "not found" and `./configure` fails with `no acceptable C compiler found in $PATH`, even though the compiler is installed — this happened on the first `configure` attempt for this build and was the actual root cause.

### Packages needed beyond Week 1's toolchain

Week 1 installed the UCRT64 `gcc` toolchain itself. wolfSSL's build additionally needs:

```bash
pacman -S autoconf automake libtool git
```

- `autoconf`/`automake`/`libtool` — generate and drive the actual `configure` script from `configure.ac`; without these, `./autogen.sh` fails with `autoreconf: command not found`.
- `git` — MSYS2's shell does not inherit the Windows PATH, so the Git for Windows install from Week 1 is invisible here; a separate `git` install (and separate `git config --global user.name`/`user.email`) is needed inside MSYS2.

---

## Getting the source

Clone as a **sibling directory to `securelink`**, not inside it — wolfSSL is a third-party dependency, not project code, and shouldn't be vendored into this repo's git history.

MSYS2's default home (`~`) is **not** your Windows user folder — it's a separate internal directory. Windows drives are reachable via the `/c/`-style mount instead:

```bash
cd /c/Users/yette
git clone https://github.com/wolfSSL/wolfssl.git
```

Result: `C:\Users\yette\wolfssl`, next to `C:\Users\yette\securelink`.

---

## Build

```bash
export MSYSTEM=UCRT64
source /etc/profile
cd /c/Users/yette/wolfssl

./autogen.sh
./configure --enable-static --disable-shared --enable-debug --prefix=/ucrt64
make
make install
```

### Flag rationale

Checked against this exact checkout's real `./configure --help` output rather than assumed from memory or web docs — flag availability/defaults vary by wolfSSL version.

| Flag | Why |
|---|---|
| `--enable-static --disable-shared` | wolfSSL builds shared-only by default (`--enable-shared` default is `yes`, `--enable-static` default is `no`). Static avoids a runtime DLL-discovery problem — same category of issue as the ASan DLL from Week 1's sanitizer pass. |
| `--enable-debug` | Consistent with `-g` used everywhere else in this project; useful once debugging handshake failures in Week 2's later days. |
| `--prefix=/ucrt64` | Installs headers/lib directly into the existing UCRT64 toolchain's own search path (`C:\msys64\ucrt64`), so no extra `-I`/`-L` flags are needed later — matches how the rest of this project already compiles. |
| `--enable-tls13` (not used) | Already the default in current wolfSSL (`--disable-tls13` is the flag that exists to turn it *off*) — passing it explicitly would be harmless but redundant. |

`--enable-examples` is also on by default, which matters below.

### Result of `make install`

Verified present:
- `C:\msys64\ucrt64\include\wolfssl\` (full header tree)
- `C:\msys64\ucrt64\lib\libwolfssl.a`

### One thing to remember when writing `client.c`/`server.c`

`configure` prints this note, easy to miss:

> Make sure your application includes `wolfssl/options.h` before any other wolfSSL headers. You can define `WOLFSSL_USE_OPTIONS_H` in your application to include this automatically.

`options.h` records which features this specific build actually has enabled/disabled. Skipping it risks the application code assuming a different feature set than what was actually compiled, causing confusing mismatches or link errors. Add `#define WOLFSSL_USE_OPTIONS_H` before any wolfSSL include in Week 2 Day 3/4's `server.c`/`client.c`.

---

## Confirming the build

Per the build log, prove the build itself works using wolfSSL's own bundled examples — before writing any project code — so a later bug can be localized to "my code" vs. "my wolfSSL build" as two separate questions.

```bash
cd /c/Users/yette/wolfssl
./examples/server/server.exe -v 4 -d &
sleep 1
./examples/client/client.exe -h 127.0.0.1 -v 4 -d
```

`-v 4` forces TLS 1.3 specifically (`-v <num>` selects protocol version 0–4, SSLv3–TLS1.3; default is 3/TLS1.2). Without it, the example defaults to TLS 1.2 — which still proves the build works, but doesn't prove the actual thing this project needs (TLS 1.3 support).

**Actual result, TLS 1.3 forced:**
```
client_out: SSL version is TLSv1.3 / I hear you fa shizzle!
server_out: SSL version is TLSv1.3 / Client message: hello wolfssl!
```

A real handshake, both sides agreeing on TLS 1.3, with a message sent and received in both directions.

### A scripting bug hit while testing (not a wolfSSL problem)

Initial attempt used:
```bash
cd /c/Users/yette/wolfssl && ./examples/server/server.exe -d &
./examples/client/client.exe -h 127.0.0.1 -d   # fails: No such file or directory
```

`cmd1 && cmd2 &` backgrounds the **entire** `cmd1 && cmd2` as one subshell — the `cd` only takes effect inside that backgrounded subshell, never in the main shell. The following `client.exe` command then resolved its relative path from the wrong directory. Fix: put `cd` on its own line, background only the server command by itself, and capture its PID via `$!` for cleanup rather than relying on job-control syntax (`%1`), which is less reliable in non-interactive shell invocations.

A second, unrelated issue on the very first (TLS 1.2, unforced) test: both processes were redirected to the *same* output file, and their concurrent writes interleaved character-by-character into unreadable garbage. Fix: redirect each process to its own file.

---

## Rebuild — Week 2, Day 3: adding `--enable-opensslextra`

Writing the mTLS verify callback needed `wolfSSL_X509_STORE_CTX_get_current_cert` and `wolfSSL_X509_get_serial_number` — both part of wolfSSL's OpenSSL-compatibility layer, gated behind `OPENSSL_EXTRA`, which Day 1's build never enabled (no way to know it'd be needed yet). Confirmed the gap concretely before touching anything: `nm libwolfssl.a | grep wolfSSL_X509_STORE_CTX_get_current_cert` returned nothing — the symbol genuinely wasn't compiled in, not just a header-visibility issue.

**Final working configure line:**
```bash
export MSYSTEM=UCRT64
source /etc/profile
cd /c/Users/yette/wolfssl
make distclean
./configure --enable-static --disable-shared --enable-debug --prefix=/ucrt64 \
    --enable-opensslextra --disable-dependency-tracking
make
make install-nobase_includeHEADERS
cp src/.libs/libwolfssl.a /ucrt64/lib/libwolfssl.a
```

Two flags different from Day 1, and the install step deliberately narrower than a plain `make install`. Each is a fix for a specific, separately-diagnosed problem:

**`--enable-opensslextra`** — the actual goal; adds the OpenSSL-compatibility API surface, including the two functions above.

**`--disable-dependency-tracking`** — works around a real autotools/MSYS2 bug, not a config choice. Re-running `./configure` (without a preceding `make distclean`) failed at the very end with `config.status: error: Something went wrong bootstrapping makefile fragments for automatic dependency tracking`. Root cause, confirmed by reading `config.log` directly: `config.status` spawns its own internal subshell to test-run `make`, and that subshell doesn't inherit the full PATH our interactive shell has — so `make: command not found` fires *inside configure itself*, corrupting the dependency-tracking bootstrap. This left a stale/wrong `libtool` script behind (its `old_archive_cmds` fell back to `lib -OUT:...`, the MSVC archiver syntax, instead of GNU `ar`) — confirmed by grepping the generated `libtool` file directly. Fix was two parts: `make distclean` to clear the corrupted intermediate state, then reconfigure with `--disable-dependency-tracking` so the buggy bootstrap step never runs. The clean reconfigure produced a correct `libtool` (`old_archive_cmds="$AR $AR_FLAGS ..."`) with zero manual patching needed.

**`make install-nobase_includeHEADERS` + manual `.a` copy, instead of `make install`** — a plain `make install` recurses into every subdirectory including `tests/`, and wolfSSL's own bundled unit-test suite (`tests/unit.test.exe`, not anything this project uses) fails to link with `undefined reference to wolfSSL_ERR_print_errors`. Traced to `wolfssl/wolfcrypt/logging.h`: that function needs `WOLFSSL_HAVE_ERROR_QUEUE`, which is defined only under `#if (defined(OPENSSL_EXTRA) && !defined(_WIN32) && ...)` — deliberately excluded on Windows by wolfSSL upstream, regardless of `OPENSSL_EXTRA`. `libwolfssl.la`/`.a` and both example binaries had already linked successfully before this unrelated failure. Rather than chase down wolfSSL's own Windows test-suite gap, installed only the actual deliverables: the top-level `install-nobase_includeHEADERS` target (headers only, doesn't touch `tests/`) plus a direct copy of the freshly built `src/.libs/libwolfssl.a`.

**A tooling gotcha worth remembering going forward**: the `Bash` tool available directly in this environment is Git Bash, not MSYS2's bash — it inherits the persistent Windows PATH (so `gcc` under `ucrt64/bin` resolves, since that was added system-wide in Week 1) but *not* MSYS2's `usr/bin`, where `make.exe`/`ar.exe`/`nm.exe` actually live. Every command touching the wolfSSL build tree has to go through `C:\msys64\usr\bin\bash.exe -lc "export MSYSTEM=UCRT64; source /etc/profile; ..."` explicitly, exactly like Day 1 — using the plain `Bash` tool alone silently fails with `command not found` for anything outside `gcc` itself.

**Verified afterward, not assumed**: `nm /ucrt64/lib/libwolfssl.a | grep wolfSSL_X509_STORE_CTX_get_current_cert` (and the equivalent for `wolfSSL_X509_get_serial_number`) both confirmed real compiled symbols present, and `src/server.c` linked clean against the rebuilt library.

---

## Rebuild — Week 3, Day 2: adding `--enable-keying-material`

`docs/PROTOCOL.md`'s HMAC key derivation needs `wolfSSL_export_keying_material()` (RFC 5705/RFC 8446 §7.5). Confirmed the gap the same way as Day 3's rebuild, not by assumption: `nm libwolfssl.a | grep export_keying_material` returned nothing, and attempting to compile against it failed with `implicit declaration of function 'wolfSSL_export_keying_material'`.

**Final working configure line:**
```bash
export MSYSTEM=UCRT64
source /etc/profile
cd /c/Users/yette/wolfSSl/wolfssl
make clean
./configure ac_cv_vcs_checkout=no \
    --enable-static --disable-shared --enable-debug --prefix=/ucrt64 \
    --enable-opensslextra --disable-dependency-tracking \
    --enable-keying-material CPPFLAGS=-DWOLFSSL_HAVE_ERROR_QUEUE
make
make install
```

Three things different from the Day 3 line, each a fix for a separately-diagnosed problem:

**`--enable-keying-material`** — the actual goal. Off by default; not tied to any heavier feature (WPA supplicant, Chrony, SRTP also enable it as a side effect, but this project needs none of those). Confirmed afterward via `grep HAVE_KEYING_MATERIAL wolfssl/options.h` and `nm libwolfssl.a | grep export_keying_material` — both present.

**`ac_cv_vcs_checkout=no`** — works around a real autotools/modern-GCC interaction, not a config choice, and had nothing to do with keying material specifically. Building directly inside a git checkout makes `configure`'s `AX_HARDEN_COMPILER_FLAGS` macro (`m4/ax_harden_compiler_flags.m4`) permanently inject `-Werror` into every subsequent internal probe — including old-style `AC_CHECK_FUNC` compatibility shims (a deliberately-mismatched `strftime` prototype, used only to confirm the symbol exists) that current GCC now flags via `-Werror=builtin-declaration-mismatch`. That single failed probe surfaced as a misleading top-level `Header file inconsistency detected -- error including wolfssl/openssl/asn1.h`, not as anything mentioning `strftime` or `-Werror` directly — traced by reading `config.log`'s actual failed-command output, not by trusting the summary error. `ac_cv_vcs_checkout` is an ordinary `AC_CACHE_CHECK` variable, so it can be pre-seeded on the command line to skip the check and its `-Werror` side effect entirely, without touching wolfSSL's own source.

**`CPPFLAGS=-DWOLFSSL_HAVE_ERROR_QUEUE`** — corrects a wrong assumption recorded in this file's Day 3 section above, that `WOLFSSL_HAVE_ERROR_QUEUE` is "deliberately excluded on Windows by wolfSSL upstream, regardless of `OPENSSL_EXTRA`." That's not accurate for this checkout (`internal.h:6991` gates it on `defined(OPENSSL_EXTRA) && defined(WOLFSSL_HAVE_ERROR_QUEUE)` only — no `_WIN32` exclusion) — it's simply not exposed as a `--enable-*` configure flag at all, only settable via a raw `CPPFLAGS` define. Worth setting now rather than continuing to route around it: without it, `make`/`make install` fail on the *unrelated* internal target `tests/unit.test.exe` (`undefined reference to wolfSSL_ERR_print_errors`), which Day 3's build sidestepped with a narrower `install-nobase_includeHEADERS` install target instead. With this flag, a plain `make install` now succeeds outright, so Day 3's narrower install workaround is no longer necessary going forward (though harmless if used).

**A transient issue hit along the way, not a real problem**: `./configure` intermittently failed with `cannot run C compiled programs` / `./conftest.exe: Permission denied` (exit 77), and later a freshly-linked `server.exe`/`client.exe`/`test_sha256.exe` intermittently failed to execute at all — confirmed via direct PowerShell invocation to be Windows Smart App Control / Application Control evaluating newly-compiled, unsigned binaries by hash, not a permissions or code problem (the identical binary ran fine again once its hash had "settled"/been evaluated). Resolved by retrying rather than by any code or configure change — a bare retry-loop around `./configure` (a handful of attempts, few-second gaps) cleared it for the build itself; freshly-linked project binaries sometimes need a similar short wait after linking before they'll execute.

### New runtime requirements this introduced in `client.c`/`server.c`

Two more things `wolfSSL_export_keying_material()` needs that aren't about the *build* at all, found by actually running a live client/server exchange rather than trusting that "it compiles" meant "it works":

- **`wolfSSL_KeepArrays(ssl)` must be called before `wolfSSL_connect()`/`wolfSSL_accept()`**, not after. wolfSSL frees its internal handshake arrays once the handshake completes (to save memory); the exporter needs them afterward. Without this, `wolfSSL_export_keying_material()` links and runs, but always returns `WOLFSSL_FAILURE` at runtime with no wolfSSL error string attached (`wolfSSL_get_error` reports `0`/`"ok"`) — traced by reading `wolfSSL_export_keying_material`'s own source (`src/ssl.c`) directly rather than guessing from the symptom, since the generic failure gave no other clue.
- **A graceful `wolfSSL_shutdown(ssl)` before `wolfSSL_free(ssl)`** on both sides, once a session ends. Without it, closing a socket that still has unread bytes sitting in its OS receive buffer (e.g. a post-handshake TLS 1.3 session ticket the peer never explicitly read) can make Winsock send a hard RST instead of a graceful FIN — which was observed concretely closing out a live test: a client's final `DISCONNECT` app-message, sent successfully (`wolfSSL_write` returned success), never arrived at the server, which sat blocked in `wolfSSL_read()` waiting for it. Confirmed as the fix, not just theorized, by re-running the same live exchange after adding the shutdown call.

`docs/BUILD.md` didn't previously document the exact `gcc`/link command line for `client.c`/`server.c` at all — worth recording here since a new library dependency showed up:

```bash
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/server.c -o build/server.o
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/client.c -o build/client.o
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/message.c -o build/message.o
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/hmac.c -o build/hmac.o
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/revocation.c -o build/revocation.o
gcc -Wall -Wextra -g -Iinclude -Isrc -c src/sha256.c -o build/sha256.o

gcc -g build/server.o build/message.o build/hmac.o build/revocation.o build/sha256.o \
    -o build/server.exe -lwolfssl -lws2_32 -lcrypt32
gcc -g build/client.o build/message.o build/hmac.o build/sha256.o \
    -o build/client.exe -lwolfssl -lws2_32 -lcrypt32
```

**`-lcrypt32`** — new as of this rebuild. `--enable-opensslextra` (already in use since Day 3) pulls in `LoadSystemCaCertsWindows()` inside wolfSSL, which calls the Windows certificate-store API (`CertOpenSystemStoreA`/`CertEnumCertificatesInStore`/`CertCloseStore`, from `crypt32.dll`) — undefined-reference at link time without it. Not something Day 3's build hit, since nothing in that build exercised the code path that pulls this symbol in until now.

---

## Related
- [[06-Reference/Command Reference|Command Reference]]
- [[02-Week 2 - TLS and mTLS/Week 2 Day 1 Walkthrough|Week 2 Day 1 Walkthrough]]

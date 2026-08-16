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

## Related
- [[06-Reference/Command Reference|Command Reference]]
- [[02-Week 2 - TLS and mTLS/Week 2 Day 1 Walkthrough|Week 2 Day 1 Walkthrough]]

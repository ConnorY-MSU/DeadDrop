# PKI_SETUP.md — Certificate Authority and Certificate Generation

Exact steps used to generate this project's private CA, server certificate, and client certificate. Written Week 2, Day 2. Every command below was actually run and its output verified — not a retroactive description.

---

## Where these files live

**`C:\Users\yette\deaddrop-pki`** — deliberately outside any git repository (not even gitignored inside one; physical separation avoids the "one `git add -f` away from a leaked key" failure mode) and outside OneDrive sync (confirmed OneDrive is scoped to `C:\Users\yette\OneDrive\` specifically; this folder is a sibling, not a child, of that path).

The folder itself has restricted NTFS permissions — inherited ACLs removed, access granted only to the local user account and `SYSTEM`:

```powershell
New-Item -ItemType Directory -Path C:\Users\yette\deaddrop-pki -Force
icacls C:\Users\yette\deaddrop-pki /inheritance:r
icacls C:\Users\yette\deaddrop-pki /grant:r "<DOMAIN>\<user>:(OI)(CI)F"
icacls C:\Users\yette\deaddrop-pki /grant:r "SYSTEM:(OI)(CI)F"
```

All commands below were run from the **MSYS2 UCRT64 terminal** (same reasoning as `docs/BUILD.md` — needs to match the toolchain the rest of the project uses), from inside that folder:

```bash
export MSYSTEM=UCRT64
source /etc/profile
cd /c/Users/yette/deaddrop-pki
```

---

## Step 1 — CA private key (RSA 4096, passphrase-protected)

```bash
openssl genrsa -aes256 -out ca_key.pem 4096
```

Passphrase-protected deliberately, and only for this key — it never needs unattended/automated access (unlike the server/client keys, which will eventually load automatically on a Pi), so there's no zero-touch-boot conflict here, only upside. 4096-bit specifically: larger than the 2048-bit leaf keys below, since this key signs everything else and is used rarely, so the extra computational cost is irrelevant while its compromise would be catastrophic.

## Step 2 — CA self-signed root certificate

```bash
openssl req -x509 -new -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem
```

Subject: `C=US, ST=Montana, L=Bozeman, O=DeadDrop, OU=Developer, CN=DeadDrop Root CA, emailAddress=yetterconnor@gmail.com`

`-x509` produces a self-signed certificate directly (this is what makes it a root CA rather than a request). `-days 3650` ≈ 10 years, appropriate for a long-lived private root.

## Step 3 — Server private key (RSA 2048, no passphrase)

```bash
openssl genrsa -out server_key.pem 2048
```

No `-aes256` — this key needs to load without a passphrase prompt, since it's headed toward an unattended Pi.

## Step 4 — Server CSR

```bash
openssl req -new -key server_key.pem -out server_csr.pem
```

Subject CN: `DeadDrop-Server` — deliberately distinct from the CA's CN, to avoid the CN-mixup class of mistake flagged in [[02-Week 2 - TLS and mTLS/X.509 and PKI Concepts|X.509 and PKI Concepts]].

## Step 5 — Sign the server CSR with the CA

```bash
openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -days 825 -sha256
```

`-CAcreateserial` creates `ca_cert.srl`, tracking serial numbers issued by this CA — directly relevant to the revocation-by-serial-number check (next task). `-days 825` ≈ 2 years, deliberately shorter than the CA's own validity.

## Step 6 — Client private key, CSR, and signed cert

Same pattern as Steps 3–5:

```bash
openssl genrsa -out client_key.pem 2048
openssl req -new -key client_key.pem -out client_csr.pem
openssl x509 -req -in client_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 825 -sha256
```

Subject CN: `DeadDrop-Client`.

## Step 7 — File permissions

```bash
chmod 600 ca_key.pem server_key.pem client_key.pem
```

**Note:** MSYS2's `chmod`/`ls -la` on NTFS is a POSIX-permission *emulation* layer and doesn't map 1:1 onto real Windows ACLs — after running this, `ls -la` still displayed `-rw-r--r--` (644), which looked wrong at first. The actual enforced permission is the folder-level `icacls` restriction set up before any of these files existed (inherited by every file created inside it, per the `(OI)(CI)` inheritance flags). Confirmed directly:

```powershell
icacls C:\Users\yette\deaddrop-pki\ca_key.pem
# -> NT AUTHORITY\SYSTEM:(I)(F)
#    <DOMAIN>\<user>:(I)(F)
```

Only the local user account and `SYSTEM` have access — no broader "Users"/"Administrators"/"Everyone" grants. On Windows, `icacls` is the ground truth for what's actually enforced; `chmod`/`ls -la` inside MSYS2 is cosmetic.

---

## Verification performed

### Field-level check, every certificate

```bash
openssl x509 -in <cert>.pem -noout -subject -issuer -serial -dates
```

| File | Subject CN | Issuer CN | Serial | Validity |
|---|---|---|---|---|
| `ca_cert.pem` | DeadDrop Root CA | DeadDrop Root CA (self-signed) | `3A16E969A5C16B51EDE568B433EAC76A57156094` | 2026-08-16 → 2036-08-13 |
| `server_cert.pem` | DeadDrop-Server | DeadDrop Root CA | `68A7E95F14813C60A047706956F72BA0CCCC83F8` | 2026-08-16 → 2028-11-18 |
| `client_cert.pem` | DeadDrop-Client | DeadDrop Root CA | `68A7E95F14813C60A047706956F72BA0CCCC83F9` | 2026-08-16 → 2028-11-18 |

Serial numbers confirmed sequential and distinct (`...83F8`, `...83F9`) — the property the revocation check depends on.

### Key encryption check

```bash
head -2 <key>.pem
```

`ca_key.pem` → `-----BEGIN ENCRYPTED PRIVATE KEY-----` (correct — passphrase-protected). `server_key.pem`/`client_key.pem` → `-----BEGIN PRIVATE KEY-----` (correct — plain, no passphrase).

### Cryptographic chain verification (not just matching text fields)

```bash
openssl verify -CAfile ca_cert.pem server_cert.pem   # server_cert.pem: OK
openssl verify -CAfile ca_cert.pem client_cert.pem   # client_cert.pem: OK
```

Both certificates cryptographically verified against the CA — proves the signatures are actually valid, not just that the issuer field contains the right string.

---

## Resulting files

Nine files in `deaddrop-pki/`: `ca_key.pem` (private, encrypted), `ca_cert.pem` (public), `ca_cert.srl`, `server_key.pem` (private, plain), `server_csr.pem`, `server_cert.pem`, `client_key.pem` (private, plain), `client_csr.pem`, `client_cert.pem`.

**What eventually goes where** (Week 4): each Pi gets its own private key + own signed cert + the CA's public cert only. `ca_key.pem` never leaves this dev machine.

## Related
- [[02-Week 2 - TLS and mTLS/X.509 and PKI Concepts|X.509 and PKI Concepts]]
- [[02-Week 2 - TLS and mTLS/Week 2 Day 2 Walkthrough|Week 2 Day 2 Walkthrough]]
- `docs/BUILD.md`

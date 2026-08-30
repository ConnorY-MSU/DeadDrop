# DeadDrop

A mutually-authenticated, end-to-end encrypted point-to-point communication system for two paired Raspberry Pi 5 field terminals — built from cryptographic first principles, with no third-party message server or relay in the application layer.

Each device is a self-contained terminal: a touchscreen, an ncurses-based UI, hardware status indicators, and text-to-speech for incoming messages. The two devices authenticate each other and exchange messages directly over a private mesh network, with no cloud backend standing between them.

## What it does

- **Real device-to-device messaging** with text, small file transfer, delivery acknowledgment, and keepalive/RTT measurement — no message server, no third party ever has access to plaintext.
- **Mutual authentication** — both devices present and verify certificates on every connection; a device with no valid certificate, an expired one, one signed by the wrong authority, or one that's been revoked is rejected outright, not just warned about.
- **Defense in depth above the transport layer** — application messages are independently authenticated and replay-protected even though they already ride an encrypted TLS 1.3 session.
- **Hardware-bound storage encryption** — a stolen or lost device's storage is unreadable on any other hardware, verified by actually trying it on different hardware, not just trusting the tooling.
- **No single point of private-key custody** — neither device holds a directly usable copy of its own long-term private key at rest.
- **A remote emergency wipe** — either paired device can trigger an irreversible wipe of message history on both ends.
- **Rigorous, empirical verification throughout** — millions of fuzz iterations, explicit negative-path testing, and a maintained, dated testing log with verbatim results, not summarized outcomes.

## Architecture, bottom to top

| Layer | What it is |
|---|---|
| **Cryptographic primitives** | SHA-256 and AES-128 hand-implemented in C directly from their published specifications and validated against NIST's official test vectors — an educational foundation, never used in the deployed trust path. All real cryptography (TLS, message authentication, disk encryption) runs on wolfSSL and the OS's own reviewed libraries. |
| **Transport security** | TLS 1.3 via [wolfSSL](https://www.wolfssl.com/), configured for mutual TLS (mTLS): both sides present and verify X.509 certificates issued by a private, purpose-built certificate authority, plus a custom certificate-revocation check inside the same verification callback that performs chain validation. |
| **Application protocol** | A self-designed binary message format (see [`docs/PROTOCOL.md`](docs/PROTOCOL.md)) layered on top of the TLS connection: fixed 12-byte header, HMAC-SHA256 trailer covering the full header and body (keyed from the TLS session's own exported keying material — RFC 5705/8446 §7.5, no separate key exchange), and a strictly-increasing per-sender sequence number enforced before any message is accepted. |
| **Network** | Devices connect over a private WireGuard-based mesh overlay ([Tailscale](https://tailscale.com/)), with a self-hosted DERP relay for the minority of connections that can't establish a direct path. The mesh's own access-control list restricts the paired devices to reaching only each other's application port, independent of anything the application enforces itself. |
| **Physical device** | Two Raspberry Pi 5 units, each with its own touchscreen, running the protocol through an ncurses terminal UI, auto-booting into the running application via a hardened systemd service. |

## Security design highlights

- **Certificate revocation, verified live** — a genuinely valid, correctly-signed, unexpired client certificate was placed on the revocation list and confirmed rejected specifically for that reason (not a generic chain failure), with the legitimate handshake path re-verified as still working immediately after.
- **Mutual key-custody scheme** — the key protecting each device's own private key file is XOR-split into two shares at provisioning time and never stored in reconstructible form on either device: one share lives locally, the complementary share lives on the *paired* device. A stolen device alone yields a share that's provably useless without the other, which never resided on that device. Reconstruction happens in memory only, at boot, after each device authenticates to its peer over the mesh network's own identity (not the mTLS credential, which is itself gated behind this step).
- **Hardware-bound full-disk encryption** — LUKS2, with the decryption key derived from a secret held in the Raspberry Pi 5's own one-time-programmable SoC fuse memory, never stored in any file or backup. Verified by physically moving a provisioned storage device to a different, otherwise-identical unit with unburned fuses: it could not be unlocked under the correct key path or multiple guessed passphrases. Returned to its original device, it auto-unlocked with zero prompts across multiple independent cold boots, including a genuinely unplanned power interruption.
- **PIN lock tuned against real hardware** — PBKDF2-HMAC-SHA256, iteration count empirically tuned on the deployed hardware to land in the low-hundreds-of-milliseconds range (an initial higher-security configuration measured ~1.9s per check — an unacceptable UX cost for a check performed on every unlock attempt). A ramping wrong-attempt delay persists across process restarts, so a crash/respawn cycle can't be used to bypass the lockout.
- **Network exposure scoped deliberately** — the main application listener binds only to the mesh network's own interface, never to "all interfaces," a real gap that was found and fixed during review and confirmed with a live cross-device test.
- **Hardened systemd service** — runs as an unprivileged user with kernel/namespace-level sandboxing directives applied (kernel tunables, module loading, control groups, SUID/SGID execution, writable+executable memory mappings, and more locked down at the process level). A small number of common hardening directives are deliberately *not* applied, each for a specific, individually-checked reason tied to a real runtime dependency (privileged network config tooling, direct hardware bus access, a real terminal device, a forked child process for speech output) — evaluated against actual source code, not assumed.
- **The private certificate authority's key no longer exists** — after issuing the two device certificates this project needs, the CA's private key was securely destroyed (multi-pass overwrite, secure delete, free-space scrub, verified against the still-valid public root certificate afterward), removing an internet-connected machine as a standing trust dependency. Any future additional device requires establishing a new CA and re-trusting existing devices — a deliberate tradeoff.

## Testing and verification

- A regression suite covering the hand-rolled cryptographic primitives, HMAC usage, certificate revocation logic, and protocol message handling runs after every meaningful code change, on the physical target devices natively — not just in a development environment. Current status: all passing, including full coverage on the revocation-check module (8/8 cases) and the protocol message-handling module (29/29 cases).
- Two fuzz harnesses, built under AddressSanitizer + UndefinedBehaviorSanitizer, target the protocol message parser and the WiFi-configuration field parser. A pass requires every iteration to either correctly parse valid input or cleanly reject invalid input — any crash, sanitizer report, or hang is an automatic fail.

  | Harness | Iterations | Result |
  |---|---|---|
  | Protocol message parser | 2,000,011 | Zero crashes, zero sanitizer findings |
  | WiFi field parser | 1,000,000+ | Zero crashes, zero sanitizer findings |

- Four distinct negative TLS scenarios were tested end-to-end against the live running server and confirmed to fail for the *specific*, correctly-identified reason: no client certificate, a certificate signed by the wrong CA, an expired certificate, and a revoked certificate — with the legitimate handshake path re-verified after each.
- A full, dated testing log with verbatim results (not summarized outcomes) is maintained in [`TESTING.md`](TESTING.md) from day one of the project onward.

## Repository layout

```
include/    Public headers for every module (crypto primitives, session, protocol, hardware drivers, UI)
src/        Implementation — crypto, TLS session handling, the application protocol, hardware modules, UI
tests/      Unit/regression tests and fuzz harnesses
tools/      Standalone utilities (e.g. key-custody share provisioning)
docs/       Protocol spec, build instructions, PKI setup, and project write-ups (see below)
```

## Documentation

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — full application protocol specification, wire format, and design rationale, written before the code that implements it
- [`docs/BUILD.md`](docs/BUILD.md) — build instructions and toolchain notes
- [`docs/PKI_SETUP.md`](docs/PKI_SETUP.md) — certificate authority and certificate generation procedure
- [`docs/PROJECT_DESCRIPTION_TECHNICAL.md`](docs/PROJECT_DESCRIPTION_TECHNICAL.md) — full technical write-up: threat model, architecture, and design rationale in depth
- [`docs/PROJECT_DESCRIPTION_SUMMARY.md`](docs/PROJECT_DESCRIPTION_SUMMARY.md) — a shorter technical summary
- [`docs/PROJECT_DESCRIPTION_PLAIN.md`](docs/PROJECT_DESCRIPTION_PLAIN.md) — a plain-language explanation for a non-technical audience
- [`TESTING.md`](TESTING.md) — the complete, dated testing log

## Status

Actively developed. The core system — crypto primitives, mutual TLS, the application protocol, mesh networking, hardware-bound disk encryption, and the physical device build — is complete and running in production on both paired devices. Additional hardware integrations (e.g. GPS-based location sharing) are in progress.

## Honest limitations

This project has not undergone a paid, professional third-party security audit, and internal review does not fully substitute for one. The application-layer protocol built on top of TLS, while fuzz-tested and carefully designed, is bespoke and has not been through formal, adversarial cryptographic review or a formal protocol model (e.g. ProVerif or Tamarin). The system depends on Tailscale's coordination infrastructure for mesh identity even with a self-hosted relay in place. There is no fully verified or cryptographically signed boot chain, so disk encryption alone does not prevent a sufficiently determined attacker with extended physical access from tampering with the bootloader or kernel. No certified hardware security module or secure enclave is used — the disk encryption's hardware root of trust is real and independently verified, but not a certified security module in the formal sense. Connection metadata (that two devices are communicating, and roughly when) remains visible to the mesh network's own coordination infrastructure.

This system is built to meaningfully raise the cost of casual, opportunistic, and moderately resourced attacks against this specific pair of devices — not to claim resistance to a funded or nation-state-level adversary. These limitations are stated directly because an accurate account of what a system does and does not protect against is itself part of a credible security posture.

## Feedback welcome

Outside review from computer science, information technology, and security professionals is genuinely welcomed — particularly on the application protocol layer in `docs/PROTOCOL.md`, since that layer hasn't yet had the benefit of formal adversarial review.

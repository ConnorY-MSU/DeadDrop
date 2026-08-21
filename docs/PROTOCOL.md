# PROTOCOL.md — SecureLink Application Protocol

This document specifies the SecureLink application-layer message protocol
carried inside an established mTLS (TLS 1.3) session. It is intended to be
sufficient on its own for an independent implementer to build a compatible
parser without reference to the source code.

## Header layout

| Offset | Size | Field         | Notes                                                                 |
|-------:|-----:|---------------|------------------------------------------------------------------------|
| 0      | 1    | `version`     | Protocol version. Currently `1`.                                       |
| 1      | 1    | `msg_type`    | See Message types below.                                               |
| 2      | 2    | `reserved`    | Must be sent as `0x0000`. Reserved for future flags.                   |
| 4      | 4    | `seq_num`     | `uint32_t`, big-endian. Per-sender monotonic sequence number. See below.|
| 8      | 4    | `body_length` | `uint32_t`, big-endian. Length of `body` in bytes only.                |
| 12     | N    | `body`        | `N = body_length` bytes. Message payload.                              |
| 12+N   | 32   | `hmac_tag`    | HMAC-SHA256 over bytes `[0, 12+N)` — the header and body.               |

Total message size on the wire is `12 + body_length + 32` bytes.

`body_length` does **not** include the 12-byte header or the 32-byte
`hmac_tag`. It counts the body only. Maximum accepted `body_length` is
**65536 bytes (64 KiB)** — generous for any realistic chat-style text
message or paste, and small enough that no plausible claimed value comes
close to memory-exhaustion territory on either dev-machine or Pi hardware.
A received message whose `body_length` exceeds this is rejected outright,
per Failure handling below.

### Sequence numbers (`seq_num`) — replay protection

Each endpoint maintains its own outgoing counter, independent of the
counter it receives from its peer (this is a bidirectional protocol; each
direction has its own sequence space). Rules:

- The first message sent by an endpoint in a given TLS session has
  `seq_num = 0`. Every subsequent message sent by that endpoint in the
  same session increments by exactly 1 — every message type consumes a
  sequence number, not just `TEXT_MESSAGE`, so there is one counter per
  sender, not one per message type.
- The sequence space resets to 0 at the start of every new TLS session.
  It is not persisted across reconnects.
- A receiver tracks the last-accepted `seq_num` from each peer. An
  incoming message is only accepted if its `seq_num` is **strictly
  greater** than the last one accepted from that same peer. This rejects
  both an exact replay (identical `seq_num` resent) and a stale message
  reinjected out of order.
- `uint32_t` wraparound (~4.3 billion messages in one session) is not
  handled specially — not a realistic concern for this project's actual
  use case, and worth stating explicitly rather than silently ignoring.

This is what actually closes the replay gap an HMAC alone doesn't cover:
the tag proves a message wasn't *altered*, `seq_num` (itself covered by
the HMAC, so it can't be stripped or rewritten independently) proves it
wasn't *replayed* within the same session. Replay *across* sessions is a
separate, narrower concern — see the HMAC key section below.

### Worked example

`msg_type = 0x01` (`TEXT_MESSAGE`), first message sent in the session
(`seq_num = 0`), body = `"hello"` (5 bytes):

```
Offset  Bytes                Meaning
0       01                   version = 1
1       01                   msg_type = TEXT_MESSAGE
2       00 00                reserved
4       00 00 00 00          seq_num = 0 (big-endian)
8       00 00 00 05          body_length = 5 (big-endian)
12      68 65 6C 6C 6F       body = "hello"
17      <32 bytes>           hmac_tag = HMAC-SHA256(bytes[0:17])
```

Total message size = 17 + 32 = 49 bytes.

## Message types

| Value  | Name           | Purpose                                             |
|--------|----------------|------------------------------------------------------|
| `0x01` | `TEXT_MESSAGE` | User-originated chat text — the core message type.   |
| `0x02` | `PING`         | Keepalive probe sent by either endpoint.             |
| `0x03` | `PONG`         | Response to a received `PING`.                       |
| `0x04` | `DISCONNECT`   | Explicit, clean notice that the session is closing.  |

Any other `msg_type` value is unrecognized. See Failure handling.

## HMAC computation and verification

- **Algorithm:** HMAC-SHA256 (32-byte output).
- **Placement:** appended as a fixed-size trailer immediately following the
  body — always the last 32 bytes of the message.
- **Coverage:** computed over the full 12-byte header *and* the body — i.e.
  every byte preceding the tag itself (`bytes[0, 12+N)`). The header is
  included (and `seq_num` specifically) so that none of `version`,
  `msg_type`, `seq_num`, or `body_length` can be tampered with or replayed
  independently of the body without invalidating the tag.
- `body_length` never includes the `hmac_tag`'s own 32 bytes.

### HMAC key derivation

The HMAC key is **not** a separate pre-shared secret — it is derived from
the already-established TLS 1.3 session itself, via the RFC 5705/RFC 8446
§7.5 keying-material exporter mechanism (`wolfSSL_export_keying_material()`
on the wolfSSL side), so no additional key-exchange step is needed beyond
the mTLS handshake already completed in Week 2.

- **Label:** `"EXPERIMENTAL-SecureLink-HMAC-Key"`. TLS exporter labels
  have an IANA registry; an ad-hoc, unregistered label like this one
  should be prefixed `EXPERIMENTAL-` per RFC 8446 §4.2.7's convention,
  specifically so it can never collide with a future officially
  registered label of the same name.
- **Context:** empty (no additional context value mixed in).
- **Output length:** 32 bytes, matching HMAC-SHA256's natural key size.

Because this key is derived fresh from each individual TLS session's own
key material, a message (and its valid tag) captured from one session
will not produce a valid tag if replayed into a *different* session — the
derived key itself differs. This is what makes the `seq_num` mechanism
above sufficient to address only *same-session* replay, rather than
needing to also solve cross-session replay independently.

**Implementation note for Day 2:** verify the exact `wolfSSL_export_keying_material()` signature and behavior against the wolfSSL manual for your installed version before implementing this — don't assume the parameters from this description alone, same discipline as every other wolfSSL API used so far in this project.

## Failure handling

| Condition | Action |
|---|---|
| `body_length` exceeds 65536 bytes (the maximum accepted) | Reject the message. Do not attempt to read a body of that size. Treat the connection's framing state as invalid. |
| Unrecognized `version` byte | Reject the message and disconnect the connection cleanly. No fallback or best-effort parsing is attempted for unknown versions. |
| Unrecognized `msg_type` byte | Reject the message; do not process the body. |
| `seq_num` not strictly greater than the last `seq_num` accepted from this peer | Reject the message; do not process the body. This is the replay/reordering check. |
| `hmac_tag` verification failure | Reject the message in its entirety. The body is never processed, regardless of whether `version`, `msg_type`, `seq_num`, and `body_length` were otherwise valid. |

In all rejection cases, the receiver does not act on any part of the
message body. Whether the connection is torn down entirely or only the
malformed message is discarded is an implementation choice, but partial
processing of a message that fails any of the above checks is not
permitted.

## Design rationale: why HMAC on top of TLS 1.3's AEAD

TLS 1.3's AEAD cipher suite already authenticates and encrypts everything
inside the session, so the application-layer HMAC is not there to catch
in-transit tampering — TLS already guarantees that. It exists as defense in
depth against bugs or misconfiguration at the TLS layer, so that a
compromise there doesn't silently give an attacker the ability to inject or
alter messages the application trusts. It also provides message integrity
that survives outside the TLS session boundary: if a message is later
logged or forwarded into a different context, the HMAC still proves it
hasn't been altered, whereas TLS's guarantees end when the session does.
Combined with the per-message `seq_num` (itself covered by the tag) and a
key derived fresh per TLS session, it additionally provides same-session
replay protection that TLS's own record-layer sequencing doesn't expose
to the application layer. Finally, it makes the protocol self-describing
and independently verifiable — integrity and freshness can both be
checked from the message bytes alone, without having to assume TLS was
configured correctly.

---

## Network transport and addressing — Week 3 Day 3

SecureLink runs over [Tailscale](https://tailscale.com/) (WireGuard-based mesh VPN) between the two devices, rather than requiring manual port forwarding or a public IP on either side. See [[WireGuard and Tailscale Concepts]] for the mechanics and the "double encryption" rationale for why an application-layer TLS session is still justified on top of WireGuard's own encryption.

### Client addressing: hardcoded Tailscale IP vs. MagicDNS

`client.c`'s `-h` argument is resolved via `getaddrinfo()`, which accepts either a raw IPv4 address (a Tailscale IP, e.g. `100.x.y.z`) or a hostname (a Tailscale MagicDNS name, e.g. `securelink-server.<tailnet>.ts.net`) through the same code path — this was previously `inet_pton()`, which only parses numeric addresses and would have silently rejected a MagicDNS hostname outright, so this had to change regardless of which addressing approach got picked. **The actual choice of which to use is still open**, deferred until a second device (a Pi, post-Week-4-Day-1 OS install) actually exists to test against — either is a one-line `-h` argument change now, not a code change.

### Tailscale ACL — restricting the two devices to reaching only each other

By default every device on a tailnet can reach every other device on it. `docs/tailscale-acl.json` is the actual policy (tag-based, so it can be written and validated before the second device exists): `tag:securelink-client` is permitted to reach `tag:securelink-server` on port 4433 only, and — since Tailscale ACLs are default-deny once any custom rule exists — nothing else is permitted in either direction, including toward/from any other device later added to this tailnet for unrelated purposes.

Applied so far: this dev machine is tagged `tag:securelink-client`. `tag:securelink-server` remains to be applied to a Pi once it's actually running Tailscale.

---

## Related
- [[Encrypt-then-MAC Concepts]]
- [[Binary Protocol Design Concepts]]
- [[Week 3 Day 1 Walkthrough]]
- [[WireGuard and Tailscale Concepts]]
- [[Week 3 Day 3 Walkthrough]]

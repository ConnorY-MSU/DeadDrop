#ifndef KEYSHARE_H
#define KEYSHARE_H

#include <stddef.h>
#include <stdint.h>

/*
 * keyshare - mutual 2-of-2 key-share protection for each device's
 * private key. See "Network-Fetched Key Protection Concepts" in the
 * project vault for the full design and threat-model reasoning; this
 * header covers the mechanics.
 *
 * THE SCHEME: each device's private key is AES-128-CTR encrypted at
 * rest with a key K (see tools/keyshare_setup.c, the one-time dev-
 * machine tool that generates K and never lets it exist anywhere
 * else). K is never itself stored, in reconstructible form, on the
 * SAME device whose key it protects - it is split via XOR into two
 * 16-byte shares:
 *   local_share  (= a random value R)   - lives on this device
 *   remote_share (= K XOR R)            - lives on the PAIRED device,
 *                                          as its custody-share for
 *                                          THIS device
 * A lone share, by itself, is information-theoretically independent
 * of K (the same guarantee a one-time pad relies on) - stealing one
 * device's SD card yields a local_share that is provably useless
 * without the remote_share, which never left the other device.
 *
 * BOOTSTRAP AUTHENTICATION: the remote_share fetch, at every startup,
 * needs authenticating - and it can't use this device's own SecureLink
 * mTLS key (that key is the very thing being unlocked). This module
 * uses Tailscale's own node identity instead, a separate credential
 * already established by Week 4 Day 1: `tailscale whois <ip>` on
 * both the listener and the fetcher confirms the peer is genuinely
 * the specific paired device, not just anyone reachable on the
 * tailnet.
 *
 * MUTUAL BOOT DEPENDENCY, BY DESIGN: reconstructing this device's own
 * key requires the paired device's listener to be reachable. This is
 * not a bug to route around - see the concept note for why it's an
 * accepted, honestly-documented tradeoff for two devices that exist
 * specifically to talk to each other. keyshare_reconstruct() retries
 * with backoff (matching client.c's own reconnect pattern) rather
 * than failing immediately.
 *
 * Linux-only (raw evdev-adjacent socket/Tailscale-CLI plumbing, same
 * category as touch.c/wifi.c) - non-Linux builds get stub functions
 * that always fail, matching this project's established precedent so
 * callers don't need #ifdef guards at every call site.
 */

#define KEYSHARE_LEN 16 /* AES-128 key size - K, R, and each share are
                            all exactly this length */

/*
 * keyshare_reconstruct - the full boot-time flow. Starts a background
 * listener bound to THIS device's Tailscale IP only, serving
 * my_custody_share_path's contents to the paired device once its
 * identity is verified; concurrently (from the caller's perspective,
 * synchronously - this call blocks until it succeeds or is told to
 * give up) connects to the peer's own listener to fetch THIS
 * device's remote_share, verifies the peer's identity on that
 * connection too, and XORs it with local_share_path's contents to
 * produce K in out_key.
 *
 * local_share_path:       file holding this device's own local_share (R).
 * peer_tailscale_ip:      the paired device's Tailscale IP to connect to.
 * peer_expected_hostname: the paired device's expected Tailscale node
 *   hostname (e.g. "securelink-bravo", matched against the short name
 *   portion of `tailscale whois`'s "Name:" field, before the tailnet's
 *   own MagicDNS suffix) - verified on every connection, incoming or
 *   outgoing, before anything is trusted or served.
 * my_custody_share_path:  file holding the custody-share THIS device
 *   holds on behalf of the peer - served to the peer's own fetch.
 * listen_port:             TCP port for the share-listener. Both devices
 *   use the same port; each binds only its own Tailscale IP, so this
 *   never collides with the peer's own listener on the same port.
 *
 * Returns 0 on success (out_key filled with K), -1 on an
 * unrecoverable local error (e.g. can't read local_share_path or
 * my_custody_share_path at all - a missing file is not something
 * retrying will fix). Network unreachability to the peer is NOT
 * unrecoverable - that's retried internally with backoff.
 */
int keyshare_reconstruct(const char *local_share_path,
                          const char *peer_tailscale_ip,
                          const char *peer_expected_hostname,
                          const char *my_custody_share_path,
                          int listen_port,
                          uint8_t out_key[KEYSHARE_LEN]);

/*
 * keyshare_stop_listener - stop the background share-listener thread
 * started by keyshare_reconstruct(). Call this at process shutdown
 * (or don't bother - the process exiting closes the socket anyway).
 *
 * REAL BUG FOUND AND FIXED via live two-Pi testing, worth recording
 * here since it shapes this contract: an earlier version of this
 * comment recommended calling this immediately after THIS device's
 * own key loaded, on the theory that the listener "only needs to
 * serve the peer once, near mutual startup." That's wrong, and it
 * caused a real, reproducible deadlock: bravo finished reconstructing
 * its own key first, immediately stopped its listener per that old
 * guidance, and alpha - which hadn't fetched its own share from bravo
 * yet - was then permanently unable to, since nothing was listening
 * on bravo's side anymore. Confirmed via `ss -tlnp` showing bravo's
 * port genuinely closed. The listener must run for the WHOLE PROCESS
 * LIFETIME, not just transiently at startup - the peer may need to
 * fetch its share at any later point too, most importantly after its
 * own INDEPENDENT reboot, which could happen hours or days after this
 * device's own startup. client.c/server.c do NOT call this function
 * after key load; it exists mainly for symmetry with ui_shutdown()'s
 * belt-and-suspenders cleanup pattern, not as a startup-time
 * optimization. Safe to call even if keyshare_reconstruct() was
 * never called (no-op).
 */
void keyshare_stop_listener(void);

/*
 * keyshare_decrypt_private_key - decrypt an AES-128-CTR-encrypted
 * private key file (produced by tools/keyshare_setup.c) into a
 * caller-owned buffer, using the K reconstructed by
 * keyshare_reconstruct(). The encrypted file's own bytes ARE the
 * ciphertext directly (no header/framing - see the setup tool for
 * why a fixed all-zero counter is safe here: K is single-use,
 * encrypting exactly this one file exactly once, never reused for a
 * second message).
 *
 * Returns the number of bytes written to out_buf (the decrypted PEM
 * key, ready to hand to wolfSSL_CTX_use_PrivateKey_buffer()), or -1
 * on error (file not found/unreadable, or out_buf_size too small for
 * the file's actual size).
 */
long keyshare_decrypt_private_key(const char *encrypted_key_path,
                                   const uint8_t key[KEYSHARE_LEN],
                                   uint8_t *out_buf, size_t out_buf_size);

#endif /* KEYSHARE_H */

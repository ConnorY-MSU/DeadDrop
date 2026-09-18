#ifndef KEYSHARE_H
#define KEYSHARE_H

#include <stddef.h>
#include <stdint.h>

/* keyshare - mutual 2-of-2 key-share protection for each device's private key via Tailscale-authenticated XOR-split custody shares. Linux-only; see COMMENT_ARCHIVE.md. */

#define KEYSHARE_LEN 16 /* AES-128 key size - K, R, and each share are all exactly this length */

/* keyshare_reconstruct - boot-time flow: serves this device's custody-share once peer identity is verified, fetches its own remote_share, reconstructs K into out_key. Blocks until success. Returns 0 on success, -1 on unrecoverable local error. See COMMENT_ARCHIVE.md. */
int keyshare_reconstruct(const char *local_share_path,
                          const char *peer_tailscale_ip,
                          const char *peer_expected_hostname,
                          const char *my_custody_share_path,
                          int listen_port,
                          uint8_t out_key[KEYSHARE_LEN]);

/* keyshare_stop_listener - stop the background share-listener thread. MUST run for the whole process lifetime - see COMMENT_ARCHIVE.md for a real deadlock this caused. */
void keyshare_stop_listener(void);

/* keyshare_decrypt_private_key - decrypt an AES-128-CTR key file (from tools/keyshare_setup.c) using K. Returns bytes written to out_buf, or -1 on error. */
long keyshare_decrypt_private_key(const char *encrypted_key_path,
                                   const uint8_t key[KEYSHARE_LEN],
                                   uint8_t *out_buf, size_t out_buf_size);

/* keyshare_get_own_tailscale_ip - `tailscale ip -4`, trimmed; lets server.c bind mTLS to the Tailscale interface, not INADDR_ANY. Returns 0 on success, -1 on failure. See COMMENT_ARCHIVE.md. */
int keyshare_get_own_tailscale_ip(char *out_ip, size_t out_ip_size);

#endif /* KEYSHARE_H */

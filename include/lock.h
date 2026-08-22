#ifndef LOCK_H
#define LOCK_H

#include <stddef.h>

/*
 * lock - salted-hash PIN storage/verification for the ncurses UI's
 * local lock screen (Week 4 Days 2-3 Part E, see
 * ncurses UI Concepts.md). Uses this project's own Week 1 sha256.c - a
 * deliberate, legitimate use of the hand-rolled primitive in the
 * shipped product, unlike Week 1's AES-128/SHA-256 generally (which
 * never appear in the TLS path itself - see 00-Start Here/Project
 * Overview).
 *
 * DECOUPLING, stated explicitly because it's load-bearing: this module
 * (and ui.c's lock-screen state built on top of it) has zero knowledge
 * of sockets, sessions, wolfSSL, or the protocol layer, and must stay
 * that way. The lock screen gates what a person standing at the device
 * can SEE and TYPE - it has no mechanism by which it could touch the
 * network/crypto layer even if it wanted to, since it's never given a
 * socket, a WOLFSSL*, or a sl_session_state* to touch. That's not an
 * accident to be careful about at every call site - it's structural:
 * this header doesn't even #include message.h or expose anything that
 * takes those types.
 *
 * Storage format: a fixed 48-byte binary file - 16 bytes of random
 * salt, followed by the 32-byte SHA-256 digest of (salt || pin). The
 * PIN itself is never stored. File permissions are set to owner-
 * read/write only (0600) on Linux - defense in depth, even though this
 * gate's actual threat model (see ncurses UI Concepts.md: reaching this
 * screen at all already requires physical possession of a powered,
 * connected device) doesn't depend on it.
 *
 * Path: lock_pin_file_path() resolves to "$HOME/.securelink/pin_hash"
 * (falling back to $USERPROFILE on Windows, for dev-machine build
 * portability only - the lock screen itself is a Linux/ncurses-only UI
 * feature, see ui.h). A single, well-known, non-configurable path
 * deliberately - it makes the Day 5 overlay-filesystem exclusion list
 * (this file must survive a reboot, same as Tailscale's state and the
 * WiFi profiles) an unambiguous item to write down, per the build log's
 * own note.
 */

#define LOCK_PIN_MIN_LEN 4
#define LOCK_PIN_MAX_LEN 64

/*
 * lock_pin_file_path - fill buf with the full resolved path to the PIN
 * hash file. Returns 0 on success, -1 if no home directory could be
 * determined (HOME/USERPROFILE both unset) or buf is too small.
 */
int lock_pin_file_path(char *buf, size_t buf_size);

/*
 * lock_pin_exists - check whether a PIN hash file is currently present
 * (i.e. whether this device has ever had a PIN set). Used to decide
 * whether the UI should start locked (a PIN exists) or start unlocked
 * with no lock configured yet (first run).
 */
int lock_pin_exists(void);

/*
 * lock_set_pin - hash `pin` with a freshly generated random salt and
 * persist salt+hash to the PIN file (creating its parent directory if
 * needed), replacing any previously stored PIN. pin_len must be within
 * [LOCK_PIN_MIN_LEN, LOCK_PIN_MAX_LEN].
 *
 * Returns 0 on success, -1 on failure (bad length, couldn't create the
 * directory, couldn't write the file).
 */
int lock_set_pin(const char *pin, size_t pin_len);

/*
 * lock_check_pin - hash `pin` with the STORED salt and compare against
 * the stored digest. Returns 1 if it matches, 0 if it doesn't match or
 * no PIN file exists at all.
 */
int lock_check_pin(const char *pin, size_t pin_len);

#endif /* LOCK_H */

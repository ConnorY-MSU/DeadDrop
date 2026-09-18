#ifndef LOCK_H
#define LOCK_H

#include <stddef.h>
#include <time.h>

/* lock - salted-hash PIN storage/verification for the ncurses UI's lock screen; decoupled from sockets/sessions/wolfSSL. Storage: 48-byte file (16-byte salt + 32-byte SHA-256 digest), 0600 on Linux, at "$HOME/.deaddrop/pin_hash". */

#define LOCK_PIN_MIN_LEN 4
#define LOCK_PIN_MAX_LEN 64

/* lock_pin_file_path - fill buf with the full resolved path to the PIN hash file. Returns 0 on success, -1 if no home directory found or buf too small. */
int lock_pin_file_path(char *buf, size_t buf_size);

/* lock_pin_exists - check whether a PIN hash file is currently present. Used to decide whether the UI should start locked or unlocked (first run). */
int lock_pin_exists(void);

/* lock_set_pin - hash `pin` with a fresh random salt, persist salt+hash to the PIN file, replacing any previous PIN. pin_len must be in [LOCK_PIN_MIN_LEN, LOCK_PIN_MAX_LEN]. Returns 0 on success, -1 on failure. */
int lock_set_pin(const char *pin, size_t pin_len);

/* lock_check_pin - hash `pin` with the STORED salt and compare against the stored digest. Returns 1 if it matches, 0 otherwise (or if no PIN file exists). */
int lock_check_pin(const char *pin, size_t pin_len);

/* Wrong-PIN rate-limit persistence (Finding #6): closes the gap where a process restart used to reset ui.c's in-memory wrong-attempt delay. See COMMENT_ARCHIVE.md. */

/* lock_get_next_allowed_time - fills *out_time with the persisted "don't allow another attempt before this time" timestamp (0 if none stored). Returns 0 on success, -1 on I/O error (treat like "no restriction"). */
int lock_get_next_allowed_time(time_t *out_time);

/* lock_set_next_allowed_time - persist `t` as the next-allowed-attempt timestamp. Returns 0 on success, -1 on failure. */
int lock_set_next_allowed_time(time_t t);

/* lock_clear_next_allowed_time - remove the persisted timestamp (called on a successful unlock). Missing file is not an error. */
void lock_clear_next_allowed_time(void);

#endif /* LOCK_H */

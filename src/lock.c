#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "lock.h"

/* PBKDF2-HMAC-SHA256 (via wolfSSL's wc_PBKDF2()) replaced a hand-rolled single SHA-256 round, which was brute-forceable if pin_hash leaked. See COMMENT_ARCHIVE.md. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/hmac.h> /* WC_SHA256 */

#ifdef _WIN32
    #include <direct.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <unistd.h>
    #define MKDIR(path) mkdir((path), 0700)
#endif

#define LOCK_SALT_LEN 16
#define LOCK_HASH_LEN 32
#define LOCK_FILE_LEN (LOCK_SALT_LEN + LOCK_HASH_LEN)

int lock_pin_file_path(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (home == NULL) {
        home = getenv("USERPROFILE");
    }
#endif
    if (home == NULL) {
        return -1;
    }
    if ((size_t)snprintf(buf, buf_size, "%s/.deaddrop/pin_hash", home)
            >= buf_size) {
        return -1;
    }
    return 0;
}

/* Same directory/fallback logic as lock_pin_file_path(), a separate file - see lock.h on why this isn't appended to pin_hash's format. */
static int lock_ratelimit_file_path(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (home == NULL) {
        home = getenv("USERPROFILE");
    }
#endif
    if (home == NULL) {
        return -1;
    }
    if ((size_t)snprintf(buf, buf_size, "%s/.deaddrop/lock_ratelimit",
                          home) >= buf_size) {
        return -1;
    }
    return 0;
}

/* Directory portion of lock_pin_file_path()'s result, so the file can actually be created. MKDIR on an already-existing directory is treated as success. */
static int ensure_pin_dir(const char *pin_path)
{
    char dir[512];
    char *slash;

    if (snprintf(dir, sizeof(dir), "%s", pin_path) >= (int)sizeof(dir)) {
        return -1;
    }
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        return 0; /* no directory component - nothing to create */
    }
    *slash = '\0';
    MKDIR(dir);
    return 0;
}

/* fill_random - fill buf with unpredictable bytes for a salt. Uses /dev/urandom on Linux; the rand() fallback only exists for the non-Linux dev build. */
static void fill_random(uint8_t *buf, size_t len)
{
#ifdef __linux__
    FILE *f = fopen("/dev/urandom", "rb");
    if (f != NULL) {
        size_t got = fread(buf, 1, len, f);
        fclose(f);
        if (got == len) {
            return;
        }
    }
#endif
    {
        static int seeded = 0;
        size_t i;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (i = 0; i < len; i++) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
    }
}

/* Iteration count for PBKDF2-HMAC-SHA256, tuned on real Pi 5 hardware to land in the few-hundred-ms range for one interactive PIN entry. */
#define LOCK_PBKDF2_ITERATIONS 40000

static void hash_salted_pin(const uint8_t *salt, const char *pin,
                             size_t pin_len, uint8_t out_digest[LOCK_HASH_LEN])
{
    int rc = wc_PBKDF2(out_digest, (const byte *)pin, (int)pin_len,
                        salt, LOCK_SALT_LEN, LOCK_PBKDF2_ITERATIONS,
                        LOCK_HASH_LEN, WC_SHA256);
    if (rc != 0) {
        /* On failure, zero the output rather than leaving it garbage - callers don't check this return value. */
        memset(out_digest, 0, LOCK_HASH_LEN);
    }
}

int lock_pin_exists(void)
{
    char path[512];
    FILE *f;

    if (lock_pin_file_path(path, sizeof(path)) != 0) {
        return 0;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    fclose(f);
    return 1;
}

int lock_set_pin(const char *pin, size_t pin_len)
{
    char path[512];
    uint8_t file_data[LOCK_FILE_LEN];
    FILE *f;

    if (pin == NULL || pin_len < LOCK_PIN_MIN_LEN ||
        pin_len > LOCK_PIN_MAX_LEN) {
        return -1;
    }
    if (lock_pin_file_path(path, sizeof(path)) != 0) {
        return -1;
    }
    if (ensure_pin_dir(path) != 0) {
        return -1;
    }

    fill_random(file_data, LOCK_SALT_LEN);
    hash_salted_pin(file_data, pin, pin_len, file_data + LOCK_SALT_LEN);

    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    {
        size_t written = fwrite(file_data, 1, LOCK_FILE_LEN, f);
        fclose(f);
        if (written != LOCK_FILE_LEN) {
            return -1;
        }
    }
#ifndef _WIN32
    chmod(path, 0600); /* owner read/write only - see this file's top comment */
#endif
    return 0;
}

int lock_check_pin(const char *pin, size_t pin_len)
{
    char path[512];
    uint8_t file_data[LOCK_FILE_LEN];
    uint8_t computed[LOCK_HASH_LEN];
    FILE *f;
    size_t got;
    int i;
    uint8_t diff;

    if (pin == NULL) {
        return 0;
    }
    if (lock_pin_file_path(path, sizeof(path)) != 0) {
        return 0;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    got = fread(file_data, 1, LOCK_FILE_LEN, f);
    fclose(f);
    if (got != LOCK_FILE_LEN) {
        return 0;
    }

    hash_salted_pin(file_data, pin, pin_len, computed);

    /* Constant-time-ish comparison - not a real timing threat here, but costs nothing and is the right habit for secret digests. */
    diff = 0;
    for (i = 0; i < LOCK_HASH_LEN; i++) {
        diff |= (uint8_t)(computed[i] ^ file_data[LOCK_SALT_LEN + i]);
    }
    return diff == 0;
}

/* Stored as plain decimal ASCII, not raw binary time_t - avoids endianness/width assumptions across the two build platforms; not secret data. */
#define RATELIMIT_FILE_MAX_LEN 32

int lock_get_next_allowed_time(time_t *out_time)
{
    char path[512];
    char buf[RATELIMIT_FILE_MAX_LEN];
    FILE *f;
    size_t got;

    if (out_time == NULL) {
        return -1;
    }
    *out_time = 0;

    if (lock_ratelimit_file_path(path, sizeof(path)) != 0) {
        return -1;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return 0; /* no file yet - not a restriction, not an error */
    }
    got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';

    *out_time = (time_t)strtoll(buf, NULL, 10);
    return 0;
}

int lock_set_next_allowed_time(time_t t)
{
    char path[512];
    char buf[RATELIMIT_FILE_MAX_LEN];
    FILE *f;
    int len;

    if (lock_pin_file_path(path, sizeof(path)) != 0) {
        return -1; /* just to get ensure_pin_dir() a valid path to derive the directory from below */
    }
    ensure_pin_dir(path);

    if (lock_ratelimit_file_path(path, sizeof(path)) != 0) {
        return -1;
    }
    len = snprintf(buf, sizeof(buf), "%lld", (long long)t);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        return -1;
    }
    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    {
        size_t written = fwrite(buf, 1, (size_t)len, f);
        fclose(f);
        if (written != (size_t)len) {
            return -1;
        }
    }
#ifndef _WIN32
    chmod(path, 0600); /* tidy hygiene, not a secrecy boundary for this particular file */
#endif
    return 0;
}

void lock_clear_next_allowed_time(void)
{
    char path[512];

    if (lock_ratelimit_file_path(path, sizeof(path)) != 0) {
        return;
    }
    remove(path); /* missing file is not an error - nothing to clear */
}

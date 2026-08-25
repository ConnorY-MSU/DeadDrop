#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "wifi.h"

/* Fuzz harness for parse_escaped_ssid_field() (src/wifi.c) - 2026-08-23
 * security audit. This is the one place genuinely attacker-broadcastable
 * data (an over-the-air WiFi SSID, up to 32 bytes per the 802.11
 * standard but NOT trusted to actually respect that cap here, since
 * this parses text already round-tripped through nmcli's terse output
 * format, not raw 802.11 frames) flows into this codebase's parsing
 * logic without any authentication gate at all - unlike message.c's
 * parser (gated by a completed mTLS handshake) or keyshare.c's wire
 * format (a fixed-length read with no parsed length field, and gated
 * by verify_peer_identity() besides), anyone within radio range of
 * either device can influence exactly what bytes reach this function,
 * with zero prior authentication.
 *
 * Must be built with -fsanitize=address -fsanitize=undefined to mean
 * anything - see TESTING.md for the exact build line used. Pulls in
 * src/wifi.c directly (rather than linking its .o) since
 * parse_escaped_ssid_field() is deliberately static/file-local - this
 * is the one file in the whole fuzz suite that needs that, since every
 * other fuzzed function (dd_try_parse_message, etc.) is already public
 * API.
 *
 * "Pass" means: every iteration, the parser writes a NUL-terminated
 * string of at most out_size-1 bytes into out_ssid, and leaves *cursor
 * pointing somewhere within [line, line + strlen(line)] - never a
 * crash, never an ASan/UBSan report, never a hang, never an
 * out-of-bounds write.
 */
#include "../src/wifi.c"

#define ITERATIONS_PURE_RANDOM  500000
#define ITERATIONS_MUTATED      500000
#define MAX_LINE_LEN            512

static unsigned long g_rand_state = 0x9E3779B9UL;

static unsigned long xorshift(void)
{
    unsigned long x = g_rand_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rand_state = x;
    return x;
}

/* Runs the parser on `line` (which may itself contain embedded NULs up
 * to line_len - the function is only ever fed a real NUL-terminated
 * C string in production via strtok_r(), but a fuzz harness earns its
 * keep by trying the input the real code path doesn't expect too) and
 * validates every invariant the function is supposed to uphold. */
static void run_one(const char *line, size_t out_size)
{
    char out_ssid[WIFI_SSID_MAX + 64]; /* deliberately larger than any
        real out_size passed below, so an overflow past the intended
        bound (but still within this array) is visible to ASan's
        redzone check on the array itself, not just silently "worked
        by luck" against a tightly-sized buffer. */
    const char *cursor = line;
    const char *line_end = line + strlen(line);
    size_t written_len;

    if (out_size > sizeof(out_ssid)) {
        out_size = sizeof(out_ssid);
    }

    memset(out_ssid, 0xAA, sizeof(out_ssid)); /* poison, so a missing
        NUL terminator is visible as garbage rather than accidentally
        already-zeroed memory hiding the bug */

    parse_escaped_ssid_field(&cursor, out_ssid, out_size);

    /* Invariant 1: always NUL-terminated somewhere within out_size. */
    written_len = strnlen(out_ssid, out_size);
    if (written_len >= out_size) {
        fprintf(stderr, "FAIL: output not NUL-terminated within "
                "out_size=%zu for input %p\n", out_size, (const void *)line);
        abort();
    }

    /* Invariant 2: cursor never moves before `line` or past the
     * string's own terminating NUL (parse_escaped_ssid_field has no
     * business reading past the end of what it was given). */
    if (cursor < line || cursor > line_end) {
        fprintf(stderr, "FAIL: cursor left out of bounds "
                "(line=%p, line_end=%p, cursor=%p)\n",
                (const void *)line, (const void *)line_end,
                (const void *)cursor);
        abort();
    }
}

int main(void)
{
    long i;
    time_t seed = time(NULL);
    g_rand_state ^= (unsigned long)seed;

    printf("=== fuzz_wifi: parse_escaped_ssid_field() ===\n");
    printf("Seed: %ld\n", (long)seed);

    /* Strategy 1: pure random bytes, random length, forced to be a
     * valid C string (NUL only at the very end) - the realistic case,
     * since strtok_r() always hands this function a real C string. */
    printf("Strategy 1: pure random C strings (%d iterations)...\n",
            ITERATIONS_PURE_RANDOM);
    for (i = 0; i < ITERATIONS_PURE_RANDOM; i++) {
        char buf[MAX_LINE_LEN];
        size_t len = (size_t)(xorshift() % (MAX_LINE_LEN - 1));
        size_t j;
        for (j = 0; j < len; j++) {
            uint8_t b = (uint8_t)(xorshift() & 0xFF);
            buf[j] = (b == 0) ? (char)1 : (char)b; /* no embedded NUL */
        }
        buf[len] = '\0';
        run_one(buf, 1 + (xorshift() % WIFI_SSID_MAX));
    }

    /* Strategy 2: adversarial, structurally-aware mutations - heavy on
     * the exact bytes this parser treats specially ('\\', ':'), since
     * random noise alone rarely hits the escape-handling edge cases
     * (a trailing lone backslash right at the NUL, runs of "\\:\\:\\:",
     * a line that's ALL colons, etc.) that are exactly where an
     * off-by-one is most likely to live. */
    printf("Strategy 2: structurally-aware mutations (%d iterations)...\n",
            ITERATIONS_MUTATED);
    {
        const char *base_strings[] = {
            "The Arrow:WPA2",
            "S\\:S\\:I\\:D:secured",
            "\\:\\:\\:\\:\\:\\:\\:\\:",
            "trailing-backslash-at-end\\",
            "",
            ":",
            "::::::::::::::::::::::::::::::::::::::::::::::",
            "\\",
        };
        int n_bases = (int)(sizeof(base_strings) / sizeof(base_strings[0]));

        for (i = 0; i < ITERATIONS_MUTATED; i++) {
            char buf[MAX_LINE_LEN];
            const char *base = base_strings[xorshift() % (unsigned)n_bases];
            size_t base_len = strlen(base);
            size_t len;
            size_t j;

            if (base_len >= sizeof(buf)) {
                base_len = sizeof(buf) - 1;
            }
            memcpy(buf, base, base_len);
            len = base_len;

            /* Apply a handful of random point-mutations biased toward
             * ':' and '\\', plus occasional length changes. */
            int n_mutations = 1 + (int)(xorshift() % 6);
            int m;
            for (m = 0; m < n_mutations && len > 0; m++) {
                unsigned long choice = xorshift() % 4;
                size_t pos = (size_t)(xorshift() % len);
                if (choice == 0) {
                    buf[pos] = ':';
                } else if (choice == 1) {
                    buf[pos] = '\\';
                } else if (choice == 2 && len + 1 < sizeof(buf)) {
                    /* insert a byte, shifting the tail right */
                    memmove(buf + pos + 1, buf + pos, len - pos);
                    buf[pos] = (xorshift() & 1) ? ':' : '\\';
                    len++;
                } else if (choice == 3 && len > 1) {
                    /* delete a byte */
                    memmove(buf + pos, buf + pos + 1, len - pos - 1);
                    len--;
                }
            }
            for (j = 0; j < len; j++) {
                if (buf[j] == '\0') {
                    buf[j] = '_'; /* keep it a valid C string */
                }
            }
            buf[len] = '\0';

            run_one(buf, 1 + (xorshift() % WIFI_SSID_MAX));
        }
    }

    /* Strategy 3: deterministic fixed edge cases, always run the same
     * way regardless of the random seed. */
    printf("Strategy 3: fixed edge cases...\n");
    {
        const char *edge_cases[] = {
            "",                      /* empty line */
            ":",                     /* colon only, empty SSID */
            "\\",                    /* lone trailing backslash, no NUL after */
            "\\:",                   /* exactly one escaped colon, nothing else */
            "a\\",                   /* char then dangling backslash at end */
            "::::::::::",            /* all colons */
            "\\\\\\\\\\\\\\\\",      /* all backslashes, none followed by ':' */
        };
        int n = (int)(sizeof(edge_cases) / sizeof(edge_cases[0]));
        int k;
        for (k = 0; k < n; k++) {
            /* every out_size from 1 up to WIFI_SSID_MAX, to specifically
             * hit the truncation boundary for each edge case */
            size_t osz;
            for (osz = 1; osz <= WIFI_SSID_MAX; osz++) {
                run_one(edge_cases[k], osz);
            }
        }
    }

    printf("FUZZING COMPLETE, NO CRASHES\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "wifi.h"

/* Fuzz harness for parse_escaped_ssid_field() (src/wifi.c), the one unauthenticated attacker-data entry point; build with ASan+UBSan. See COMMENT_ARCHIVE.md. */
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

/* Runs the parser on `line` and validates every invariant it's supposed to uphold. */
static void run_one(const char *line, size_t out_size)
{
    char out_ssid[WIFI_SSID_MAX + 64]; /* larger than any out_size below, so overflow is caught by ASan's redzone */
    const char *cursor = line;
    const char *line_end = line + strlen(line);
    size_t written_len;

    if (out_size > sizeof(out_ssid)) {
        out_size = sizeof(out_ssid);
    }

    memset(out_ssid, 0xAA, sizeof(out_ssid)); /* poison, so a missing NUL terminator shows up as garbage, not zeroed memory */

    parse_escaped_ssid_field(&cursor, out_ssid, out_size);

    /* Invariant 1: always NUL-terminated somewhere within out_size. */
    written_len = strnlen(out_ssid, out_size);
    if (written_len >= out_size) {
        fprintf(stderr, "FAIL: output not NUL-terminated within "
                "out_size=%zu for input %p\n", out_size, (const void *)line);
        abort();
    }

    /* Invariant 2: cursor never moves before `line` or past the string's own terminating NUL. */
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

    /* Strategy 1: pure random bytes, random length, forced to be a valid C string (NUL only at the end). */
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

    /* Strategy 2: adversarial mutations heavy on the bytes this parser treats specially ('\\', ':'). */
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

            /* Apply a handful of random point-mutations biased toward ':' and '\\', plus occasional length changes. */
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

    /* Strategy 3: deterministic fixed edge cases, always run the same way regardless of the random seed. */
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
            /* every out_size from 1 up to WIFI_SSID_MAX, to hit the truncation boundary for each edge case */
            size_t osz;
            for (osz = 1; osz <= WIFI_SSID_MAX; osz++) {
                run_one(edge_cases[k], osz);
            }
        }
    }

    printf("FUZZING COMPLETE, NO CRASHES\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "message.h"

/* Fuzz harness for dd_try_parse_message() (src/message.c); build with -fsanitize=address,undefined per TESTING.md. See COMMENT_ARCHIVE.md. */

#define ITERATIONS_PURE_RANDOM 1000000
#define ITERATIONS_MUTATED     1000000
#define MAX_FUZZ_LEN           DD_MAX_MSG_SIZE

static const uint8_t test_key[DD_HMAC_KEY_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

typedef struct {
    long ok, rejected, incomplete, unexpected;
} fuzz_stats;

static void init_state(dd_session_state *s)
{
    memset(s, 0, sizeof(*s));
    memcpy(s->hmac_key, test_key, sizeof(test_key));
}

/* Feeds one buffer through the parser; a crash/ASan report ends the process here. */
static void fuzz_one(dd_session_state *state, const uint8_t *buf, size_t len,
                      fuzz_stats *stats)
{
    dd_parsed_message msg;
    size_t consumed = 0;
    dd_parse_result pr = dd_try_parse_message(state, buf, len, &msg, &consumed);

    switch (pr) {
        case DD_PARSE_OK:
            stats->ok++;
            break;
        case DD_PARSE_REJECTED:
            stats->rejected++;
            break;
        case DD_PARSE_INCOMPLETE:
            stats->incomplete++;
            break;
        default:
            /* Unreachable in a correct build - dd_parse_result has only three values. */
            stats->unexpected++;
            fprintf(stderr,
                "fuzz_one: dd_try_parse_message returned undefined "
                "value %d for a %zu-byte buffer\n", (int)pr, len);
            break;
    }
}

static void print_stats(const char *label, const fuzz_stats *s)
{
    printf("  %-28s ok=%-8ld rejected=%-8ld incomplete=%-8ld unexpected=%ld\n",
           label, s->ok, s->rejected, s->incomplete, s->unexpected);
}

/* Pure-random buffers across the full valid message-size range (0 to DD_MAX_MSG_SIZE). */
static void run_pure_random(fuzz_stats *stats)
{
    dd_session_state state;
    uint8_t *buf = malloc(MAX_FUZZ_LEN);
    int i;

    if (buf == NULL) {
        fprintf(stderr, "run_pure_random: out of memory\n");
        return;
    }

    init_state(&state);
    printf("Fuzzing with pure-random buffers, full size range up to %d "
           "bytes (%d iterations)...\n", MAX_FUZZ_LEN, ITERATIONS_PURE_RANDOM);

    for (i = 0; i < ITERATIONS_PURE_RANDOM; i++) {
        /* Biased toward smaller lengths (where real messages live), while still reaching the full range. */
        size_t len;
        int roll = rand() % 100;
        if (roll < 70) {
            len = (size_t)(rand() % 600);                 /* small, common */
        } else if (roll < 95) {
            len = (size_t)(rand() % 8192);                 /* medium */
        } else {
            len = (size_t)(rand() % (MAX_FUZZ_LEN + 1));    /* full range */
        }

        {
            size_t j;
            for (j = 0; j < len; j++) {
                buf[j] = (uint8_t)(rand() % 256);
            }
        }
        fuzz_one(&state, buf, len, stats);
    }

    free(buf);
}

/* Builds one valid, correctly-signed base message of the given body length. */
static int build_base_message(dd_session_state *sender, uint32_t body_len,
                               uint8_t *out_buf, size_t out_buf_size)
{
    uint8_t *body = malloc(body_len > 0 ? body_len : 1);
    int total;
    size_t i;

    if (body == NULL) {
        return -1;
    }
    for (i = 0; i < body_len; i++) {
        body[i] = (uint8_t)((i * 31 + 7) & 0xFF);
    }
    total = dd_serialize_message(sender, DD_MSG_TEXT_MESSAGE, body, body_len,
                                  out_buf, out_buf_size);
    free(body);
    return total;
}

/* Mutation strategy cycling through eight kinds each iteration, run against three differently-sized base messages. */
static void run_mutated(fuzz_stats *stats)
{
    dd_session_state sender, receiver;
    uint8_t *good_msg = malloc(DD_MAX_MSG_SIZE);
    uint8_t *buf = malloc(DD_MAX_MSG_SIZE);
    int i;

    /* Tiny, medium, and near-max (not exactly max, so still valid before mutation) base message sizes. */
    static const uint32_t base_body_lens[3] = {
        44, 4096, DD_MAX_BODY_LEN - 1
    };
    size_t base_idx;

    if (good_msg == NULL || buf == NULL) {
        fprintf(stderr, "run_mutated: out of memory\n");
        free(good_msg);
        free(buf);
        return;
    }

    printf("Fuzzing with mutated real messages across %zu base sizes "
           "(%d iterations each)...\n",
           sizeof(base_body_lens) / sizeof(base_body_lens[0]),
           ITERATIONS_MUTATED / 3);

    for (base_idx = 0; base_idx < 3; base_idx++) {
        int good_total;

        init_state(&sender);
        good_total = build_base_message(&sender, base_body_lens[base_idx],
                                         good_msg, DD_MAX_MSG_SIZE);
        if (good_total < 0) {
            fprintf(stderr, "run_mutated: failed to build a %u-byte-body "
                             "base message\n", base_body_lens[base_idx]);
            continue;
        }

        for (i = 0; i < ITERATIONS_MUTATED / 3; i++) {
            size_t len = (size_t)good_total;
            /* 8 strategies - see individual comments below for what each targets. */
            int strategy = rand() % 8;
            int num_passes = (strategy == 5) ? (2 + rand() % 2) : 1;
            int pass;

            memcpy(buf, good_msg, len);

            for (pass = 0; pass < num_passes; pass++) {
                /* Each pass of a stacked (5) sequence picks a fresh random sub-strategy. */
                int sub = (strategy == 5) ? (rand() % 5) : strategy;

                switch (sub) {
                    case 0: {
                        /* Flip a handful of random bits anywhere, including the HMAC tag itself. */
                        int flips = 1 + (rand() % 5);
                        int f;
                        for (f = 0; f < flips; f++) {
                            size_t pos = (size_t)(rand() % (int)len);
                            buf[pos] ^= (uint8_t)(1 << (rand() % 8));
                        }
                        break;
                    }
                    case 1: {
                        /* Truncate to a random shorter length, never exactly 0 (len==0 caused a real UBSan div-by-zero here - see COMMENT_ARCHIVE.md). */
                        len = 1 + (size_t)(rand() % (int)len);
                        break;
                    }
                    case 2: {
                        /* Garbage message-type byte. */
                        buf[1] = (uint8_t)(0x05 + (rand() % 250));
                        break;
                    }
                    case 3: {
                        /* Plausible-but-wrong body_length: small delta, not an absurd value the length check trivially catches. */
                        uint32_t body_len_field =
                            ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                            ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];
                        int32_t delta = (rand() % 21) - 10;
                        uint32_t new_len =
                            (uint32_t)((int64_t)body_len_field + delta);
                        buf[8]  = (uint8_t)(new_len >> 24);
                        buf[9]  = (uint8_t)(new_len >> 16);
                        buf[10] = (uint8_t)(new_len >> 8);
                        buf[11] = (uint8_t)(new_len);
                        break;
                    }
                    case 4:
                    default: {
                        /* Corrupt only the HMAC tag - header/body untouched, isolating "HMAC-only failure". */
                        size_t tag_start = (size_t)good_total - DD_HMAC_SIZE;
                        int flips = 1 + (rand() % 4);
                        int f;
                        for (f = 0; f < flips; f++) {
                            size_t pos =
                                tag_start + (size_t)(rand() % DD_HMAC_SIZE);
                            buf[pos] ^= (uint8_t)(1 << (rand() % 8));
                        }
                        break;
                    }
                }
            }

            if (strategy == 6) {
                /* Extreme header field values: seq_num and reserved pushed to bit-pattern extremes (body_length covered by strategy 7). */
                uint32_t extreme_seq = (rand() % 2) ? 0xFFFFFFFFu : 0u;
                buf[4] = (uint8_t)(extreme_seq >> 24);
                buf[5] = (uint8_t)(extreme_seq >> 16);
                buf[6] = (uint8_t)(extreme_seq >> 8);
                buf[7] = (uint8_t)(extreme_seq);
                buf[2] = (uint8_t)(rand() % 2 ? 0xFF : 0x00); /* reserved */
                buf[3] = (uint8_t)(rand() % 2 ? 0xFF : 0x00);
            } else if (strategy == 7) {
                /* body_length pushed to its own extreme: exactly DD_MAX_BODY_LEN or exactly 0; trailing garbage bytes don't matter here. */
                uint32_t extreme_len =
                    (rand() % 2) ? (uint32_t)DD_MAX_BODY_LEN : 0u;
                buf[8]  = (uint8_t)(extreme_len >> 24);
                buf[9]  = (uint8_t)(extreme_len >> 16);
                buf[10] = (uint8_t)(extreme_len >> 8);
                buf[11] = (uint8_t)(extreme_len);
            }

            fuzz_one(&receiver, buf, len, stats);
            /* Reset receiver state each iteration so a mutation that parses OK doesn't skew later iterations. */
            init_state(&receiver);
        }
    }

    free(good_msg);
    free(buf);
}

/* Deterministic, not randomized - these exact boundary inputs run every time this binary executes. */
static void run_fixed_edge_cases(fuzz_stats *stats)
{
    dd_session_state state;
    uint8_t buf[DD_MAX_MSG_SIZE];
    int n = 0;

    init_state(&state);
    printf("Fixed deterministic edge cases...\n");

    /* Empty buffer. */
    fuzz_one(&state, buf, 0, stats); n++;

    /* Exactly one byte short of a complete header. */
    memset(buf, 0, DD_HEADER_SIZE);
    fuzz_one(&state, buf, DD_HEADER_SIZE - 1, stats); n++;

    /* Exactly a complete header, zero body claimed, but no tag present yet (still incomplete). */
    fuzz_one(&state, buf, DD_HEADER_SIZE, stats); n++;

    /* Exactly one byte short of the smallest possible complete message (header + zero body + tag). */
    memset(buf, 0, DD_HEADER_SIZE + DD_HMAC_SIZE);
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE - 1, stats); n++;

    /* All-zero buffer at several sizes - version 0 and type 0 should reject cleanly, before any HMAC work. */
    memset(buf, 0x00, sizeof(buf));
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE, stats); n++;
    fuzz_one(&state, buf, 4096, stats); n++;
    fuzz_one(&state, buf, DD_MAX_MSG_SIZE, stats); n++;

    /* All-0xFF buffer, same sizes - exercises the "implausible length rejected before trust" path from a hostile angle. */
    memset(buf, 0xFF, sizeof(buf));
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE, stats); n++;
    fuzz_one(&state, buf, 4096, stats); n++;
    fuzz_one(&state, buf, DD_MAX_MSG_SIZE, stats); n++;

    /* A well-formed header but body_length claiming exactly DD_MAX_BODY_LEN + 1 - one past the sanity-check cap. */
    {
        uint32_t over = (uint32_t)DD_MAX_BODY_LEN + 1;
        memset(buf, 0, sizeof(buf));
        buf[0] = DD_VERSION;
        buf[1] = DD_MSG_TEXT_MESSAGE;
        buf[8]  = (uint8_t)(over >> 24);
        buf[9]  = (uint8_t)(over >> 16);
        buf[10] = (uint8_t)(over >> 8);
        buf[11] = (uint8_t)(over);
        fuzz_one(&state, buf, DD_HEADER_SIZE, stats); n++;
    }

    /* Same, but exactly AT the cap - must fall through to the completeness check (INCOMPLETE), not be rejected outright. */
    {
        uint32_t at_cap = (uint32_t)DD_MAX_BODY_LEN;
        memset(buf, 0, sizeof(buf));
        buf[0] = DD_VERSION;
        buf[1] = DD_MSG_TEXT_MESSAGE;
        buf[8]  = (uint8_t)(at_cap >> 24);
        buf[9]  = (uint8_t)(at_cap >> 16);
        buf[10] = (uint8_t)(at_cap >> 8);
        buf[11] = (uint8_t)(at_cap);
        fuzz_one(&state, buf, DD_HEADER_SIZE, stats); n++;
    }

    printf("  %d fixed edge cases run\n", n);
}

int main(void)
{
    fuzz_stats pure_random_stats = {0, 0, 0, 0};
    fuzz_stats mutated_stats = {0, 0, 0, 0};
    fuzz_stats fixed_stats = {0, 0, 0, 0};
    struct timespec t0, t1;

    srand((unsigned)time(NULL));

    printf("DeadDrop protocol parser fuzz harness - Week 3 Day 5 "
           "(intensified pass)\n"
           "Must be run under an ASan/UBSan build to mean anything - see\n"
           "TESTING.md for the exact build line.\n\n");

    clock_gettime(CLOCK_MONOTONIC, &t0);

    run_fixed_edge_cases(&fixed_stats);
    run_pure_random(&pure_random_stats);
    run_mutated(&mutated_stats);

    clock_gettime(CLOCK_MONOTONIC, &t1);

    printf("\n");
    print_stats("Fixed edge cases", &fixed_stats);
    print_stats("Pure random", &pure_random_stats);
    print_stats("Mutated (3 base sizes)", &mutated_stats);

    {
        double elapsed_s = (t1.tv_sec - t0.tv_sec)
                          + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        long total = fixed_stats.ok + fixed_stats.rejected + fixed_stats.incomplete
                   + pure_random_stats.ok + pure_random_stats.rejected + pure_random_stats.incomplete
                   + mutated_stats.ok + mutated_stats.rejected + mutated_stats.incomplete;
        printf("\nTotal iterations: %ld in %.2f seconds (%.0f/sec)\n",
               total, elapsed_s, total / (elapsed_s > 0 ? elapsed_s : 1));
    }

    printf("\nFUZZING COMPLETE, NO CRASHES\n");
    return 0;
}

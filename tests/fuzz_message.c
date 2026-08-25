#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "message.h"

/* Fuzz harness for dd_try_parse_message() (src/message.c) - Week 3 Day 5,
 * intensified beyond the walkthrough's baseline example after an explicit
 * request to make this "super intensive" rather than just meeting the
 * minimum bar. Must be built with -fsanitize=address -fsanitize=undefined
 * to mean anything - see TESTING.md for the exact build line used.
 *
 * "Pass" means: every single iteration, the parser either correctly
 * parses well-formed input or cleanly returns DD_PARSE_REJECTED /
 * DD_PARSE_INCOMPLETE - never crashes, never triggers an ASan/UBSan
 * report, never hangs. A sanitizer report aborts the process mid-run and
 * is unmistakable in the output; a clean "FUZZING COMPLETE, NO CRASHES"
 * with exit code 0 is what "passed" looks like.
 *
 * What's more intensive here than the original pass:
 *  - 10x the iteration count (1,000,000 per strategy instead of 100,000)
 *  - pure-random buffers now span the FULL valid message-size range
 *    (up to DD_MAX_MSG_SIZE, ~64KB) instead of being capped at 512 bytes -
 *    the original range barely touched realistic message sizes at all
 *  - mutation fuzzing now runs against THREE base messages of very
 *    different sizes (tiny/medium/near-max body), not just one ~44-byte
 *    message - a bug that only manifests on large-message code paths
 *    (e.g. buffer-boundary arithmetic near DD_MAX_BODY_LEN) would never
 *    have been reachable by mutating only a small message
 *  - three new mutation strategies (stacked multi-mutation, extreme
 *    header field values, same-length pure garbage) alongside the
 *    original five
 *  - a deterministic fixed-edge-case pass (not randomized at all) that
 *    always runs the same specific boundary inputs every time, so those
 *    specific cases are guaranteed covered rather than left to chance
 */

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

/* Feeds one buffer through the parser and confirms it returns one of the
 * three defined outcomes. A crash/ASan report during this call ends the
 * whole process - there is nothing further to check in that case, since
 * it never returns. */
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
            /* Genuinely should be unreachable - dd_parse_result has
             * exactly three values. If this ever fires, that IS the
             * finding: the parser returned something outside its own
             * defined contract. */
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

/* Pure-random buffers, full valid-message-size range (0 to
 * DD_MAX_MSG_SIZE) - not capped at some small arbitrary length. Real
 * messages this project actually sends span this whole range (a
 * DISCONNECT is 44 bytes, a max-size TEXT_MESSAGE is ~64KB), so the
 * fuzzer should too. */
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
        /* Bias toward smaller lengths (where real messages actually
         * live) while still reaching the full range regularly - a flat
         * distribution over 0..65580 would spend disproportionate time
         * near the top end where every single byte has to be randomized
         * (slow) for comparatively little additional coverage value
         * beyond confirming large lengths are handled at all, which a
         * smaller sample of large buffers already establishes. */
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

/* Builds one valid, correctly-signed base message of the given body
 * length, filled with a repeating but non-trivial byte pattern (not all
 * zero/all same byte, so a bug that depends on body content isn't
 * accidentally masked by uniform content). */
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

/* Mutation strategy, cycling through eight kinds each iteration, run
 * against three differently-sized base messages in turn (tiny/medium/
 * near-max) rather than just one small one - specifically targeting the
 * "subtly wrong, not obviously wrong" input class [[Memory Safety Testing
 * Concepts]] calls out as the real blind spot, and specifically exercising
 * large-message code paths a single small base message never would. */
static void run_mutated(fuzz_stats *stats)
{
    dd_session_state sender, receiver;
    uint8_t *good_msg = malloc(DD_MAX_MSG_SIZE);
    uint8_t *buf = malloc(DD_MAX_MSG_SIZE);
    int i;

    /* Tiny (44-byte body, ~86-byte message), medium (4KB body), and
     * near-max (DD_MAX_BODY_LEN - 1, deliberately not exactly the max so
     * this is still a genuinely valid message before any mutation, not
     * something already sitting on the rejection boundary). */
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
            /* 8 strategies now instead of 5 - see individual comments
             * below for what each targets. */
            int strategy = rand() % 8;
            int num_passes = (strategy == 5) ? (2 + rand() % 2) : 1;
            int pass;

            memcpy(buf, good_msg, len);

            for (pass = 0; pass < num_passes; pass++) {
                /* strategy 5 (stacked) picks a FRESH random sub-strategy
                 * on each pass rather than reusing 5 itself, so "stacked"
                 * actually means "apply several DIFFERENT mutations
                 * together", not the same one repeated. */
                int sub = (strategy == 5) ? (rand() % 5) : strategy;

                switch (sub) {
                    case 0: {
                        /* Flip a handful of random bits anywhere,
                         * including the HMAC tag itself. */
                        int flips = 1 + (rand() % 5);
                        int f;
                        for (f = 0; f < flips; f++) {
                            size_t pos = (size_t)(rand() % (int)len);
                            buf[pos] ^= (uint8_t)(1 << (rand() % 8));
                        }
                        break;
                    }
                    case 1: {
                        /* Truncate to a random shorter length, but never
                         * to exactly 0 - the empty-buffer case is
                         * already covered deterministically by
                         * run_fixed_edge_cases(), and letting len reach
                         * 0 here made every OTHER case's `rand() %
                         * (int)len` (e.g. case 0 picking a byte position
                         * to flip) a division-by-zero once a stacked
                         * iteration's later pass ran against an
                         * already-zeroed len - a real UBSan/ASan catch
                         * hit while building this, in this harness, not
                         * in message.c. */
                        len = 1 + (size_t)(rand() % (int)len);
                        break;
                    }
                    case 2: {
                        /* Garbage message-type byte. */
                        buf[1] = (uint8_t)(0x05 + (rand() % 250));
                        break;
                    }
                    case 3: {
                        /* Plausible-but-wrong body_length: small delta,
                         * not an absurd value the length check trivially
                         * catches. */
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
                        /* Corrupt only the HMAC tag - header/body
                         * untouched, isolating "HMAC-only failure". */
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
                /* Extreme header field values, on top of whatever the
                 * base message had - seq_num and reserved pushed to
                 * their bit-pattern extremes. body_length is
                 * deliberately left alone here (strategy 7 covers that
                 * specific extreme separately, since combining both at
                 * once would make it hard to tell which one mattered if
                 * something were ever found). */
                uint32_t extreme_seq = (rand() % 2) ? 0xFFFFFFFFu : 0u;
                buf[4] = (uint8_t)(extreme_seq >> 24);
                buf[5] = (uint8_t)(extreme_seq >> 16);
                buf[6] = (uint8_t)(extreme_seq >> 8);
                buf[7] = (uint8_t)(extreme_seq);
                buf[2] = (uint8_t)(rand() % 2 ? 0xFF : 0x00); /* reserved */
                buf[3] = (uint8_t)(rand() % 2 ? 0xFF : 0x00);
            } else if (strategy == 7) {
                /* body_length pushed to its own extreme: exactly
                 * DD_MAX_BODY_LEN (the largest value that must still be
                 * accepted as "plausible" and go on to the completeness
                 * check, not rejected outright the way MAX+1 would be)
                 * or exactly 0. Buffer bytes beyond the original message
                 * are untouched garbage from the base message reused
                 * across iterations - fine, since the point is exercising
                 * the length-vs-available-bytes comparison itself, not
                 * producing a coherent message. */
                uint32_t extreme_len =
                    (rand() % 2) ? (uint32_t)DD_MAX_BODY_LEN : 0u;
                buf[8]  = (uint8_t)(extreme_len >> 24);
                buf[9]  = (uint8_t)(extreme_len >> 16);
                buf[10] = (uint8_t)(extreme_len >> 8);
                buf[11] = (uint8_t)(extreme_len);
            }

            fuzz_one(&receiver, buf, len, stats);
            /* Reset receiver state each iteration so a mutation that
             * happens to parse OK doesn't move every later iteration's
             * replay baseline. */
            init_state(&receiver);
        }
    }

    free(good_msg);
    free(buf);
}

/* Deterministic, not randomized - the same specific boundary inputs run
 * every single time this binary executes, so these exact cases are
 * guaranteed covered rather than left to chance the way the randomized
 * passes above are. */
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

    /* Exactly a complete header, zero body claimed, but no tag present
     * yet (still incomplete overall). */
    fuzz_one(&state, buf, DD_HEADER_SIZE, stats); n++;

    /* Exactly one byte short of the smallest possible complete message
     * (header + zero body + tag). */
    memset(buf, 0, DD_HEADER_SIZE + DD_HMAC_SIZE);
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE - 1, stats); n++;

    /* All-zero buffer at several sizes, including exactly the smallest
     * possible complete message - version 0 and type 0 are both
     * unrecognized, so this should reject cleanly on that basis alone,
     * well before any HMAC computation happens on it. */
    memset(buf, 0x00, sizeof(buf));
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE, stats); n++;
    fuzz_one(&state, buf, 4096, stats); n++;
    fuzz_one(&state, buf, DD_MAX_MSG_SIZE, stats); n++;

    /* All-0xFF buffer, same sizes - version 0xFF and a claimed
     * body_length of 0xFFFFFFFF specifically exercises the "implausible
     * length rejected before being trusted for anything, including the
     * completeness check itself" path from a maximally hostile angle. */
    memset(buf, 0xFF, sizeof(buf));
    fuzz_one(&state, buf, DD_HEADER_SIZE + DD_HMAC_SIZE, stats); n++;
    fuzz_one(&state, buf, 4096, stats); n++;
    fuzz_one(&state, buf, DD_MAX_MSG_SIZE, stats); n++;

    /* A well-formed header (correct version, valid msg_type) but with
     * body_length claiming exactly DD_MAX_BODY_LEN + 1 - one past the
     * cap, the exact boundary the length-sanity-check exists for. */
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

    /* Same, but exactly AT the cap (DD_MAX_BODY_LEN, not over it) - this
     * must be treated as plausible and fall through to the completeness
     * check (INCOMPLETE, since the actual bytes aren't present), not
     * rejected outright the way MAX+1 is. */
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

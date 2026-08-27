/*
 * hw_tts.c - see include/hw_tts.h for the full contract. Linux-only,
 * same "reviewed, not yet run against real hardware" status as
 * hw_expansion.c/hw_oled.c - the part most worth real verification once
 * hardware exists is "is piper/aplay actually installed, does the
 * voice model load correctly, is audio actually audible, does a
 * killed-and-respawned pipeline genuinely cut off in-progress audio
 * within an acceptable delay, and does the crash-recovery path below
 * actually recover from a real piper crash", not "did this code
 * correctly implement some external spec".
 *
 * Architecture (2026-08-25 - resident pipeline + queue; crash recovery
 * added same day):
 *
 *   [queue: bounded array, mutex+condvar, mirrors outbox.c's style]
 *          |
 *          v
 *   [speaker thread: dequeues one text at a time, writes to piper's
 *    persistent stdin. Also owns piper_pid/aplay_pid, handles
 *    stop_requested (destroy) by killing+respawning immediately, and
 *    periodically health-checks the pipeline even while idle so an
 *    unexpected crash gets noticed and healed without needing a new
 *    message to reveal it.]
 *          |
 *          v
 *   [piper process, resident, stdin=pipe we keep open, stdout=pipe to aplay]
 *          |
 *          v
 *   [aplay process, resident, stdin=pipe from piper]
 *
 * Both piper and aplay are direct (not orphaned/double-forked) children
 * of this process - deliberate, since both hw_tts_stop_and_clear() and
 * the crash-recovery path need to kill()/waitpid() them by a PID this
 * code still owns and trusts, which the double-fork-and-orphan trick
 * (correct for the original fire-and-forget one-shot design) would make
 * needlessly awkward.
 */

#ifdef __linux__

#include "hw_tts.h"

#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

/* A sane spoken-aloud length cap - this project's messages can be up to
 * DD_MAX_BODY_LEN (64KB) per PROTOCOL.md, and nobody wants that read
 * aloud in full. Deliberately not tied to DD_MAX_BODY_LEN (message.h
 * isn't even included here) - this is a UX choice about what's
 * reasonable to speak, unrelated to the protocol's own length limit. */
#define HW_TTS_MAX_CHARS 200

/* Bounded queue - mirrors outbox.c's exact style (fixed array, no
 * malloc, no linked-list bookkeeping) rather than inventing a different
 * pattern for what's structurally the same kind of problem: a
 * thread-safe FIFO between one producer (whichever thread calls
 * hw_tts_speak() - currently session.c's receiver thread) and one
 * consumer (the speaker thread below). 20 is generous for actual chat
 * pace, matching OUTBOX_MAX_MESSAGES's own reasoning - this is not
 * meant to be a long-term store-and-forward buffer. */
#define HW_TTS_QUEUE_MAX 20
#define HW_TTS_QUEUE_MSG_LEN (HW_TTS_MAX_CHARS + 2) /* text + '\n' + '\0' */

/* Crash-recovery backoff - same doubling pattern and same exact values
 * as RECONNECT_INITIAL_DELAY_SECONDS/RECONNECT_MAX_DELAY_SECONDS
 * (client.c) and BACKOFF_INITIAL_SECONDS/BACKOFF_MAX_SECONDS
 * (keyshare.c), reused deliberately rather than inventing new numbers -
 * this project already has an established, reasoned convention for
 * "something died unexpectedly, retry with growing backoff rather than
 * either busy-looping or giving up permanently." */
#define HW_TTS_RESTART_BACKOFF_INITIAL_S 1
#define HW_TTS_RESTART_BACKOFF_MAX_S     30

/* If the pipeline that just died had been alive at least this long
 * first, treat the next restart as a fresh, isolated incident (reset
 * backoff to initial) rather than punishing it with backoff grown from
 * a possibly-unrelated earlier crash - mirrors client.c's
 * reconnect_delay reset-on-actual-success logic. Reusing the max
 * backoff value here too: "survived at least as long as we'd ever wait
 * between retries" is a reasonable, simple bar for "this looks healthy
 * now." */
#define HW_TTS_RESTART_HEALTHY_UPTIME_S HW_TTS_RESTART_BACKOFF_MAX_S

/* How often the speaker thread wakes up on its own (even with an empty
 * queue) specifically to check the pipeline is still alive. Without
 * this, an unexpected piper/aplay death while no messages are arriving
 * would go undetected indefinitely - the whole point of "just in case
 * it dies" healing is not depending on the next message to reveal the
 * problem. */
#define HW_TTS_HEALTH_CHECK_INTERVAL_S 2

static char queue[HW_TTS_QUEUE_MAX][HW_TTS_QUEUE_MSG_LEN];
static int queue_head;
static int queue_count;

static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int stop_requested;      /* hw_tts_stop_and_clear() sets this */
static int shutdown_requested;  /* hw_tts_shutdown() sets this */

static pthread_t speaker_tid;
static int speaker_running; /* 0 until hw_tts_init() successfully starts
                                the thread - every public entry point
                                checks this and no-ops if unset, same
                                "absence is always non-fatal" contract */

static pid_t piper_pid = -1;
static pid_t aplay_pid = -1;
static int   piper_stdin_fd = -1; /* held open across many messages -
                                      THIS is what keeps piper resident
                                      rather than seeing EOF and exiting
                                      after one line */

/* Only ever touched from the speaker thread itself (both the initial
 * spawn from hw_tts_init(), which runs before the thread starts, and
 * every respawn thereafter, which runs ON the thread) - see this file's
 * top comment. No mutex needed for these three + the two below. */
static time_t pipeline_started_at;
static int    restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;

/* Redirect the calling process's own stdout/stderr to /dev/null. Used
 * for aplay's child specifically - same fix as the original espeak-ng
 * bug (2026-08-24, see git history): under this project's systemd
 * hardening (ProtectHome=read-only), audio libraries that try to touch
 * a config directory under $HOME print a failure straight to whatever
 * stdio they inherited, which on the real deployed service is the live
 * console (StandardError=tty), corrupting the ncurses UI. Silencing
 * stdio here, not loosening the sandbox, is the correct fix - aplay
 * doesn't need that directory to actually work. */
static void silence_stdio(void)
{
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) {
            close(devnull);
        }
    }
}

/* Same as silence_stdio() but leaves STDOUT_FILENO untouched - for
 * piper's child specifically, whose stdout is the audio pipe to aplay
 * and must stay that way. Only stderr gets silenced here. */
static void silence_stderr_only(void)
{
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        if (devnull != STDERR_FILENO) {
            close(devnull);
        }
    }
}

/* Kill (if running) and forget the current piper/aplay pids - used by
 * spawn_pipeline()'s own error cleanup, hw_tts_stop_and_clear()'s
 * handling, and the crash-recovery path below. SIGKILL, not SIGTERM:
 * for the destroy path this project wants in-progress audio to stop as
 * close to immediately as possible (see hw_tts_stop_and_clear()'s
 * header comment); for the crash-recovery path a process already
 * misbehaving badly enough to need forced recovery doesn't get the
 * benefit of the doubt either. */
static void kill_pipeline(void)
{
    if (piper_pid > 0) {
        kill(piper_pid, SIGKILL);
        waitpid(piper_pid, NULL, 0);
        piper_pid = -1;
    }
    if (aplay_pid > 0) {
        kill(aplay_pid, SIGKILL);
        waitpid(aplay_pid, NULL, 0);
        aplay_pid = -1;
    }
    if (piper_stdin_fd >= 0) {
        close(piper_stdin_fd);
        piper_stdin_fd = -1;
    }
}

/* Spawn a fresh piper+aplay pair, wired stdin->stdout->stdin as a real
 * pipeline (piper --output-raw | aplay), and leave piper_stdin_fd open
 * as our persistent handle for feeding future messages. Returns 0 on
 * success, -1 on any failure (piper_pid/aplay_pid/piper_stdin_fd are
 * left in a clean -1 state either way - callers don't need their own
 * cleanup on failure). On success, records pipeline_started_at for the
 * crash-recovery backoff-reset logic below. Called from hw_tts_init(),
 * from hw_tts_stop_and_clear()'s handling, and from the crash-recovery
 * path. */
static int spawn_pipeline(void)
{
    int text_pipe[2];  /* [0] read = piper's stdin, [1] write = ours (persistent) */
    int audio_pipe[2]; /* [0] read = aplay's stdin, [1] write = piper's stdout */
    char rate_str[16];

    if (pipe(text_pipe) != 0) {
        return -1;
    }
    if (pipe(audio_pipe) != 0) {
        close(text_pipe[0]);
        close(text_pipe[1]);
        return -1;
    }

    piper_pid = fork();
    if (piper_pid < 0) {
        close(text_pipe[0]); close(text_pipe[1]);
        close(audio_pipe[0]); close(audio_pipe[1]);
        piper_pid = -1;
        return -1;
    }
    if (piper_pid == 0) {
        /* Child: becomes piper, resident - reads lines from stdin for
         * as long as the write end (held by the parent below) stays
         * open, synthesizing and writing raw PCM to stdout per line,
         * never exiting on its own between messages. Must close every
         * fd this process doesn't need - an unused inherited copy of a
         * pipe end left open can silently prevent EOF from ever being
         * seen by the correct reader. */
        dup2(text_pipe[0], STDIN_FILENO);
        dup2(audio_pipe[1], STDOUT_FILENO);
        silence_stderr_only();
        close(text_pipe[0]);
        close(text_pipe[1]);
        close(audio_pipe[0]);
        close(audio_pipe[1]);

        /* execl(), not execlp() - piper is deliberately looked up by
         * absolute path, not via PATH search. See HW_TTS_PIPER_PATH's
         * comment in hw_tts.h for why (venv install, PATH not to be
         * trusted under the hardened systemd service). */
        execl(HW_TTS_PIPER_PATH, "piper",
              "--model", HW_TTS_MODEL_PATH,
              "--output-raw",
              (char *)NULL);
        _exit(127); /* only reached if execl() failed */
    }

    snprintf(rate_str, sizeof(rate_str), "%d", HW_TTS_SAMPLE_RATE_HZ);

    aplay_pid = fork();
    if (aplay_pid < 0) {
        close(text_pipe[0]); close(text_pipe[1]);
        close(audio_pipe[0]); close(audio_pipe[1]);
        kill(piper_pid, SIGKILL);
        waitpid(piper_pid, NULL, 0);
        piper_pid = -1;
        aplay_pid = -1;
        return -1;
    }
    if (aplay_pid == 0) {
        /* Child: becomes aplay, resident for as long as piper (its
         * upstream) stays alive and audio keeps arriving. */
        dup2(audio_pipe[0], STDIN_FILENO);
        silence_stdio();
        close(text_pipe[0]);
        close(text_pipe[1]);
        close(audio_pipe[0]);
        close(audio_pipe[1]);

        execlp("aplay", "aplay",
               "-r", rate_str,
               "-f", "S16_LE",
               "-t", "raw",
               "-",
               (char *)NULL);
        _exit(127);
    }

    /* This process (the speaker thread): keep text_pipe[1] open as our
     * persistent write handle - THIS is what makes piper stay resident
     * rather than seeing EOF and exiting after one line, since piper's
     * stdin (text_pipe[0]) only sees EOF once every write-end reference
     * is closed, and this is now the only one left. Close everything
     * else - we have no further use for the raw fd numbers, only the
     * dup'd copies each child now holds as its own stdin/stdout. */
    piper_stdin_fd = text_pipe[1];
    close(text_pipe[0]);
    close(audio_pipe[0]);
    close(audio_pipe[1]);
    pipeline_started_at = time(NULL);
    return 0;
}

/* Non-blocking check: are both piper and aplay still actually running?
 * waitpid(..., WNOHANG) returns 0 if the child is still alive, or a
 * positive pid / -1 if it has already exited (and reaps it, avoiding a
 * zombie either way) - either non-zero result means "gone." Called on
 * every speaker-thread loop iteration, whether idle or about to speak,
 * so an unexpected death is noticed regardless of whether new messages
 * are actively arriving. */
static int pipeline_is_alive(void)
{
    if (piper_pid <= 0 || aplay_pid <= 0) {
        return 0;
    }
    if (waitpid(piper_pid, NULL, WNOHANG) != 0) {
        return 0;
    }
    if (waitpid(aplay_pid, NULL, WNOHANG) != 0) {
        return 0;
    }
    return 1;
}

/* The actual crash-recovery step: apply/grow backoff as appropriate,
 * wait, then respawn. Called from the speaker thread whenever
 * pipeline_is_alive() reports the pipeline is gone AND this wasn't a
 * deliberate stop_requested (destroy) kill - that path already does
 * its own immediate kill+respawn with backoff reset, since a destroy is
 * not a crash and shouldn't be throttled by unrelated crash-loop
 * history. */
static void attempt_restart(void)
{
    time_t now = time(NULL);

    if (now - pipeline_started_at >= HW_TTS_RESTART_HEALTHY_UPTIME_S) {
        /* Ran fine for a good while before dying - treat this as an
         * isolated incident, not evidence of a persistently broken
         * install. */
        restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;
    } else {
        /* Died fast (or never started at all) - this looks like a real
         * crash loop (missing binary, bad model file, etc). Grow the
         * wait before trying again rather than hammering fork()/exec()
         * in a tight loop. */
        restart_backoff_s *= 2;
        if (restart_backoff_s > HW_TTS_RESTART_BACKOFF_MAX_S) {
            restart_backoff_s = HW_TTS_RESTART_BACKOFF_MAX_S;
        }
    }

    kill_pipeline(); /* clean up whatever's left, if anything */
    sleep((unsigned int)restart_backoff_s);
    spawn_pipeline(); /* best-effort - on failure piper_pid/aplay_pid
                          stay -1, pipeline_is_alive() will report dead
                          again on the very next check, and this
                          function runs again at the now-grown backoff.
                          No separate "give up" state: this retries
                          indefinitely, matching keyshare.c's
                          retry-forever-with-backoff philosophy rather
                          than failing permanently. */
}

static void *speaker_thread_main(void *arg)
{
    (void)arg;

    for (;;) {
        char text[HW_TTS_QUEUE_MSG_LEN];
        size_t text_len;
        int have_text = 0;

        pthread_mutex_lock(&queue_mutex);
        while (queue_count == 0 && !stop_requested && !shutdown_requested) {
            struct timespec deadline;
            int wait_rc;

            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += HW_TTS_HEALTH_CHECK_INTERVAL_S;

            wait_rc = pthread_cond_timedwait(&queue_cond, &queue_mutex,
                                              &deadline);
            if (wait_rc == ETIMEDOUT) {
                /* Periodic wakeup, nothing queued - break out to run
                 * the health check below, then loop back into this
                 * wait if there's still nothing to speak. */
                break;
            }
        }

        if (shutdown_requested) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        if (stop_requested) {
            queue_head = 0;
            queue_count = 0;
            stop_requested = 0;
            pthread_mutex_unlock(&queue_mutex);

            kill_pipeline();
            spawn_pipeline();
            /* An explicit destroy is not a crash - don't let backoff
             * grown from some earlier, unrelated crash-loop carry over
             * and needlessly delay the destroy's own respawn. */
            restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;
            continue;
        }

        if (queue_count > 0) {
            strncpy(text, queue[queue_head], sizeof(text) - 1);
            text[sizeof(text) - 1] = '\0';
            queue_head = (queue_head + 1) % HW_TTS_QUEUE_MAX;
            queue_count--;
            have_text = 1;
        }
        pthread_mutex_unlock(&queue_mutex);

        /* Health check - runs every iteration, whether this was an
         * idle periodic wakeup or we just dequeued a real message.
         * Catches an unexpected piper/aplay death regardless of
         * whether new messages happen to be arriving at the time. */
        if (!pipeline_is_alive()) {
            attempt_restart();
        }

        if (have_text) {
            text_len = strlen(text);
            if (piper_stdin_fd >= 0 && text_len > 0) {
                if (write(piper_stdin_fd, text, text_len) < 0) {
                    /* Pipeline died in the narrow window between the
                     * health check above and this write - recover now.
                     * This one utterance is still lost (piper never
                     * received it), but the pipeline itself heals for
                     * the next one rather than staying silently broken
                     * until the next periodic health check. */
                    attempt_restart();
                }
            }
        }
    }

    return NULL;
}

int hw_tts_init(void)
{
    { /* TEMP DEBUG marker - bypasses all stdio/journal/tty redirection
         complexity by writing directly to a file. Remove once resolved. */
        FILE *mf = fopen("/tmp/hw_tts_reached.marker", "w");
        if (mf) { fprintf(mf, "hw_tts_init() reached\n"); fclose(mf); }
    }

    if (speaker_running) {
        return 0; /* already running - idempotent */
    }

    queue_head = 0;
    queue_count = 0;
    stop_requested = 0;
    shutdown_requested = 0;
    restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;

    if (spawn_pipeline() != 0) {
        return -1;
    }

    if (pthread_create(&speaker_tid, NULL, speaker_thread_main, NULL) != 0) {
        kill_pipeline();
        return -1;
    }

    speaker_running = 1;
    return 0;
}

void hw_tts_speak(const char *text)
{
    char truncated[HW_TTS_MAX_CHARS + 1];
    size_t len;

    if (!speaker_running || text == NULL) {
        return;
    }

    len = strlen(text);
    if (len > HW_TTS_MAX_CHARS) {
        len = HW_TTS_MAX_CHARS;
    }
    memcpy(truncated, text, len);
    truncated[len] = '\0';

    pthread_mutex_lock(&queue_mutex);
    if (queue_count >= HW_TTS_QUEUE_MAX) {
        /* Full - silently drop (see hw_tts.h's contract on why this is
         * fine for TTS specifically, unlike outbox.c's queue). */
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    {
        int tail = (queue_head + queue_count) % HW_TTS_QUEUE_MAX;
        snprintf(queue[tail], sizeof(queue[tail]), "%s\n", truncated);
        queue_count++;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

void hw_tts_stop_and_clear(void)
{
    if (!speaker_running) {
        return;
    }
    pthread_mutex_lock(&queue_mutex);
    stop_requested = 1;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    /* Deliberately NOT waiting here for the speaker thread to finish
     * the kill+respawn - see hw_tts.h's contract: this call must stay
     * fast and never block the destroy path itself. */
}

void hw_tts_shutdown(void)
{
    if (!speaker_running) {
        return;
    }

    pthread_mutex_lock(&queue_mutex);
    shutdown_requested = 1;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    pthread_join(speaker_tid, NULL);
    kill_pipeline();
    speaker_running = 0;
}

#endif /* __linux__ */

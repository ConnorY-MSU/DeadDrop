/* hw_tts.c - see include/hw_tts.h for the contract. Linux-only, resident piper+aplay pipeline fed by a bounded queue, speaker thread also handles crash recovery. See COMMENT_ARCHIVE.md. */

#ifdef __linux__

#include "hw_tts.h"

#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

/* Spoken-aloud length cap, independent of DD_MAX_BODY_LEN (a UX choice, not a protocol limit); raised from 200 to 4096 (2026-08-27). */
#define HW_TTS_MAX_CHARS 4096

/* Bounded queue (fixed array, no malloc), mirrors outbox.c's style; one producer (hw_tts_speak()), one consumer (speaker thread). */
#define HW_TTS_QUEUE_MAX 20
#define HW_TTS_QUEUE_MSG_LEN (HW_TTS_MAX_CHARS + 2) /* text + '\n' + '\0' */

/* Crash-recovery backoff - same doubling pattern/values as client.c's RECONNECT_* and keyshare.c's BACKOFF_* constants. */
#define HW_TTS_RESTART_BACKOFF_INITIAL_S 1
#define HW_TTS_RESTART_BACKOFF_MAX_S     30

/* If the pipeline survived at least this long before dying, treat the next restart as a fresh incident and reset backoff. */
#define HW_TTS_RESTART_HEALTHY_UPTIME_S HW_TTS_RESTART_BACKOFF_MAX_S

/* How often the speaker thread wakes up on its own to check the pipeline is still alive, so a death during idle periods still gets healed. */
#define HW_TTS_HEALTH_CHECK_INTERVAL_S 2

static char queue[HW_TTS_QUEUE_MAX][HW_TTS_QUEUE_MSG_LEN];
static int queue_head;
static int queue_count;

static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int stop_requested;      /* hw_tts_stop_and_clear() sets this */
static int shutdown_requested;  /* hw_tts_shutdown() sets this */

static pthread_t speaker_tid;
static int speaker_running; /* 0 until hw_tts_init() succeeds; every public entry point checks this and no-ops if unset */

static pid_t piper_pid = -1;
static pid_t aplay_pid = -1;
static int   piper_stdin_fd = -1; /* held open across messages - keeps piper resident instead of exiting on EOF after one line */
static int   piper_out_fd = -1;   /* piper's raw-PCM stdout, read by the relay thread (not connected directly to aplay's stdin) */
static int   aplay_in_fd = -1;    /* aplay's stdin, written by the relay thread with gain-scaled samples */
static pthread_t relay_tid;

/* Real software-applied output gain (hw_tts.h's hw_tts_set_volume() - the hardware/ALSA mixer path has zero effect on loudness). */
static int g_volume_percent = 100;
static pthread_mutex_t gain_mutex = PTHREAD_MUTEX_INITIALIZER;

void hw_tts_set_volume(int percent)
{
    if (percent < 0) {
        percent = 0;
    } else if (percent > 100) {
        percent = 100;
    }
    pthread_mutex_lock(&gain_mutex);
    g_volume_percent = percent;
    pthread_mutex_unlock(&gain_mutex);
}

int hw_tts_get_volume(void)
{
    int v;
    pthread_mutex_lock(&gain_mutex);
    v = g_volume_percent;
    pthread_mutex_unlock(&gain_mutex);
    return v;
}

/* volume_relay_thread_main - sits between piper's raw PCM stdout and aplay's stdin, scaling every 16-bit sample by the current gain; exits on EOF/error, carries an odd leftover byte across read() calls. */
/* Argument block for volume_relay_thread_main() - heap-allocated per spawn so the thread has its own stable copy of the fds; thread frees this itself. */
struct relay_args {
    int in_fd;
    int out_fd;
};

static void *volume_relay_thread_main(void *arg)
{
    int in_fd = ((struct relay_args *)arg)->in_fd;
    int out_fd = ((struct relay_args *)arg)->out_fd;
    unsigned char buf[4096];
    free(arg);
    unsigned char carry_byte = 0;
    int have_carry = 0;

    for (;;) {
        ssize_t n;
        unsigned char *p = buf;
        size_t len = 0;
        float gain;
        size_t i;

        if (have_carry) {
            buf[0] = carry_byte;
            n = read(in_fd, buf + 1, sizeof(buf) - 1);
            if (n <= 0) {
                break;
            }
            len = (size_t)n + 1;
            have_carry = 0;
        } else {
            n = read(in_fd, buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            len = (size_t)n;
        }

        if (len % 2 != 0) {
            carry_byte = p[len - 1];
            have_carry = 1;
            len--;
        }

        pthread_mutex_lock(&gain_mutex);
        gain = (float)g_volume_percent / 100.0f;
        pthread_mutex_unlock(&gain_mutex);

        for (i = 0; i + 1 < len; i += 2) {
            int16_t sample;
            int32_t scaled;
            memcpy(&sample, p + i, sizeof(sample));
            scaled = (int32_t)((float)sample * gain);
            if (scaled > 32767) {
                scaled = 32767;
            } else if (scaled < -32768) {
                scaled = -32768;
            }
            sample = (int16_t)scaled;
            memcpy(p + i, &sample, sizeof(sample));
        }

        {
            size_t written = 0;
            while (written < len) {
                ssize_t w = write(out_fd, p + written, len - written);
                if (w <= 0) {
                    goto done;
                }
                written += (size_t)w;
            }
        }
    }
done:
    return NULL;
}

/* Only ever touched from the speaker thread itself (initial spawn runs before the thread starts, every respawn runs on it) - no mutex needed. */
static time_t pipeline_started_at;
static int    restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;

/* Redirect the calling process's stdout/stderr to /dev/null - used for aplay's child, whose stray output would corrupt the ncurses UI. See COMMENT_ARCHIVE.md. */
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

/* Same as silence_stdio() but leaves STDOUT_FILENO untouched - piper's stdout is the audio pipe to aplay and must stay that way. */
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

/* Kill (if running) and forget the current piper/aplay pids - used by spawn_pipeline()'s error cleanup, hw_tts_stop_and_clear(), and crash recovery. SIGKILL, not SIGTERM: gone immediately, no benefit of the doubt. */
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
    /* Closing these unblocks volume_relay_thread_main()'s blocking read()/write(), letting it notice and exit on its own. */
    if (piper_out_fd >= 0) {
        close(piper_out_fd);
        piper_out_fd = -1;
    }
    if (aplay_in_fd >= 0) {
        close(aplay_in_fd);
        aplay_in_fd = -1;
    }
}

/* Spawn a fresh piper+aplay pipeline (piper --output-raw | aplay), leaving piper_stdin_fd open as our persistent handle. Returns 0/-1; records pipeline_started_at. */
static int spawn_pipeline(void)
{
    int text_pipe[2];      /* [0] read = piper's stdin, [1] write = ours (persistent) */
    int piper_out_pipe[2]; /* [0] read = ours (relay thread), [1] write = piper's stdout */
    int aplay_in_pipe[2];  /* [0] read = aplay's stdin, [1] write = ours (relay thread) */
    char rate_str[16];

    if (pipe(text_pipe) != 0) {
        return -1;
    }
    if (pipe(piper_out_pipe) != 0) {
        close(text_pipe[0]);
        close(text_pipe[1]);
        return -1;
    }
    if (pipe(aplay_in_pipe) != 0) {
        close(text_pipe[0]);
        close(text_pipe[1]);
        close(piper_out_pipe[0]);
        close(piper_out_pipe[1]);
        return -1;
    }

    piper_pid = fork();
    if (piper_pid < 0) {
        close(text_pipe[0]); close(text_pipe[1]);
        close(piper_out_pipe[0]); close(piper_out_pipe[1]);
        close(aplay_in_pipe[0]); close(aplay_in_pipe[1]);
        piper_pid = -1;
        return -1;
    }
    if (piper_pid == 0) {
        /* Child: becomes piper, resident; stdout goes to piper_out_pipe (relay thread, software volume) not straight to aplay - see hw_tts.h's hw_tts_set_volume(). */
        dup2(text_pipe[0], STDIN_FILENO);
        dup2(piper_out_pipe[1], STDOUT_FILENO);
        silence_stderr_only();
        close(text_pipe[0]);
        close(text_pipe[1]);
        close(piper_out_pipe[0]);
        close(piper_out_pipe[1]);
        close(aplay_in_pipe[0]);
        close(aplay_in_pipe[1]);

        /* execl(), not execlp() - piper is deliberately looked up by absolute path, not via PATH search. See HW_TTS_PIPER_PATH in hw_tts.h. */
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
        close(piper_out_pipe[0]); close(piper_out_pipe[1]);
        close(aplay_in_pipe[0]); close(aplay_in_pipe[1]);
        kill(piper_pid, SIGKILL);
        waitpid(piper_pid, NULL, 0);
        piper_pid = -1;
        aplay_pid = -1;
        return -1;
    }
    if (aplay_pid == 0) {
        /* Child: becomes aplay, resident while piper stays alive; stdin comes from aplay_in_pipe (relay thread's gain-scaled output), not directly from piper. */
        dup2(aplay_in_pipe[0], STDIN_FILENO);
        silence_stdio();
        close(text_pipe[0]);
        close(text_pipe[1]);
        close(piper_out_pipe[0]);
        close(piper_out_pipe[1]);
        close(aplay_in_pipe[0]);
        close(aplay_in_pipe[1]);

        /* -D plughw:vc4hdmi0,0 - target the hardware device by name (card index isn't stable across hotplug), bypassing dmix. Two real bugs found fixing this - see COMMENT_ARCHIVE.md. */
        execlp("aplay", "aplay",
               "-D", "plughw:vc4hdmi0,0",
               "-r", rate_str,
               "-f", "S16_LE",
               "-t", "raw",
               "-",
               (char *)NULL);
        _exit(127);
    }

    /* Keep text_pipe[1] open as our persistent write handle - keeps piper resident rather than seeing EOF after one line; same idea for the audio pipes below. */
    piper_stdin_fd = text_pipe[1];
    piper_out_fd = piper_out_pipe[0];
    aplay_in_fd = aplay_in_pipe[1];
    close(text_pipe[0]);
    close(piper_out_pipe[1]);
    close(aplay_in_pipe[0]);

    {
        struct relay_args *ra = malloc(sizeof(*ra));
        if (ra == NULL) {
            close(piper_out_fd);
            close(aplay_in_fd);
            piper_out_fd = -1;
            aplay_in_fd = -1;
            return -1;
        }
        ra->in_fd = piper_out_fd;
        ra->out_fd = aplay_in_fd;
        if (pthread_create(&relay_tid, NULL, volume_relay_thread_main, ra) != 0) {
            free(ra);
            close(piper_out_fd);
            close(aplay_in_fd);
            piper_out_fd = -1;
            aplay_in_fd = -1;
            return -1;
        }
        /* Detached - nothing needs to join it; it exits and cleans itself up when kill_pipeline() closes these same fds out from under it. */
        pthread_detach(relay_tid);
    }

    pipeline_started_at = time(NULL);
    return 0;
}

/* Non-blocking check: are both piper and aplay still running? waitpid(..., WNOHANG) reaps and reports "gone" the moment either has exited. */
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

/* Crash-recovery step: grow/reset backoff, wait, then respawn. Called when pipeline_is_alive() reports the pipeline gone (not a deliberate stop_requested kill). */
static void attempt_restart(void)
{
    time_t now = time(NULL);

    if (now - pipeline_started_at >= HW_TTS_RESTART_HEALTHY_UPTIME_S) {
        /* Ran fine for a good while before dying - treat as an isolated incident, not a persistently broken install. */
        restart_backoff_s = HW_TTS_RESTART_BACKOFF_INITIAL_S;
    } else {
        /* Died fast (or never started) - looks like a real crash loop; grow the wait rather than hammering fork()/exec() in a tight loop. */
        restart_backoff_s *= 2;
        if (restart_backoff_s > HW_TTS_RESTART_BACKOFF_MAX_S) {
            restart_backoff_s = HW_TTS_RESTART_BACKOFF_MAX_S;
        }
    }

    kill_pipeline(); /* clean up whatever's left, if anything */
    sleep((unsigned int)restart_backoff_s);
    spawn_pipeline(); /* best-effort - failure just means the next health check retries at the grown backoff; retries indefinitely */
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
                /* Periodic wakeup, nothing queued - break out to run the health check below. */
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
            /* An explicit destroy is not a crash - don't let backoff from some earlier crash-loop delay the destroy's own respawn. */
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

        /* Health check - runs every iteration (idle wakeup or real message), catches an unexpected piper/aplay death either way. */
        if (!pipeline_is_alive()) {
            attempt_restart();
        }

        if (have_text) {
            text_len = strlen(text);
            if (piper_stdin_fd >= 0 && text_len > 0) {
                if (write(piper_stdin_fd, text, text_len) < 0) {
                    /* Pipeline died between the health check above and this write - recover now; this one utterance is lost but the pipeline heals. */
                    attempt_restart();
                }
            }
        }
    }

    return NULL;
}

int hw_tts_init(void)
{
    { /* TEMP DEBUG marker - writes directly to a file, bypassing stdio/journal/tty redirection; remove once resolved. */
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
        /* Full - silently drop (fine for TTS specifically, unlike outbox.c's queue - see hw_tts.h's contract). */
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
    /* Deliberately NOT waiting for the speaker thread to finish the kill+respawn - this call must stay fast and never block the destroy path. */
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

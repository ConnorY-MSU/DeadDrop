#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wardrive.h"
#include "wifi.h"

#ifdef __linux__

#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

/* --- Tuning --- */

/* How often the background thread re-evaluates, once enabled. Deliberately
 * not too aggressive - nmcli scans are ~4-6s of subprocess/radio work each
 * (see wifi.c's WIFI_SCAN_SETTLE_SECONDS), and this runs unattended for
 * hours/days, so there's no reason to burn radio time and CPU constantly. */
#define WARDRIVE_CHECK_INTERVAL_SECONDS 45

/* Ignore anything weaker than this - a barely-there open AP is more likely
 * to connect, fail to actually pass traffic, and get immediately
 * re-evaluated next cycle (churn) than to be genuinely useful. */
#define WARDRIVE_MIN_SIGNAL_PERCENT 25

/* When already on a network wardrive itself connected to, only replace it
 * with a different open network if the candidate is at least this much
 * stronger - avoids flapping between two open networks of near-equal
 * signal as it naturally fluctuates from one scan to the next. */
#define WARDRIVE_SWITCH_MARGIN_PERCENT 15

/* Every connection wardrive itself makes is saved under this name prefix
 * (plus the SSID) instead of nmcli's default (the bare SSID) - lets this
 * file recognize "a network I connected to" vs. "a trusted network the
 * user or NetworkManager's own autoconnect put me on", and lets it prune
 * its own old profiles without ever touching one it didn't create. */
#define WARDRIVE_CONN_NAME_PREFIX "wardrive-"

/* --- Persisted on/off state, same ~/.deaddrop convention as msglog.c's
 * msglog_file_path()/ensure_log_dir() - deliberately duplicated rather than
 * shared, same reasoning as msglog.c's own comment on that pattern. See
 * COMMENT_ARCHIVE.md. --- */

static int wardrive_state_file_path(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
    if (home == NULL) {
        return -1;
    }
    if ((size_t)snprintf(buf, buf_size, "%s/.deaddrop/wardrive_enabled",
                          home) >= buf_size) {
        return -1;
    }
    return 0;
}

static void ensure_state_dir(const char *state_path)
{
    char dir[512];
    char *slash;

    if (snprintf(dir, sizeof(dir), "%s", state_path) >= (int)sizeof(dir)) {
        return;
    }
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        return;
    }
    *slash = '\0';
    mkdir(dir, 0700);
}

static int load_persisted_state(void)
{
    char path[512];
    FILE *f;
    int enabled = 0;

    if (wardrive_state_file_path(path, sizeof(path)) != 0) {
        return 0;
    }
    f = fopen(path, "r");
    if (f == NULL) {
        return 0; /* no file yet = default off */
    }
    {
        int c = fgetc(f);
        enabled = (c == '1');
    }
    fclose(f);
    return enabled;
}

static void persist_state(int enabled)
{
    char path[512];
    FILE *f;

    if (wardrive_state_file_path(path, sizeof(path)) != 0) {
        return;
    }
    ensure_state_dir(path);
    f = fopen(path, "w");
    if (f == NULL) {
        return; /* best-effort, same as msglog.c's write path */
    }
    fputc(enabled ? '1' : '0', f);
    fclose(f);
}

/* --- Shared state --- */

static pthread_mutex_t wardrive_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wardrive_cond = PTHREAD_COND_INITIALIZER;
static pthread_t wardrive_tid;
static int wardrive_thread_running = 0;
static int wardrive_should_stop = 0;
static int wardrive_enabled = 0; /* protected by wardrive_mutex */

/* The SSID wardrive itself most recently connected to, or "" if none this
 * run. Used to tell "a network I put myself on" apart from "a trusted
 * network the user/NetworkManager put me on" - see wardrive_evaluate(). */
static char wardrive_last_connected_ssid[WIFI_SSID_MAX] = "";

/* --- Core decision logic --- */

static void wardrive_evaluate(void)
{
    wifi_link_info link;
    int on_our_connection;
    wifi_open_network results[WIFI_SCAN_MAX_RESULTS];
    int n, i, best;
    char conn_name[WIFI_SSID_MAX + 16];
    char err[256];

    if (wifi_get_link_info(&link) != 0) {
        link.ssid[0] = '\0';
        link.signal_percent = -1;
    }

    pthread_mutex_lock(&wardrive_mutex);
    on_our_connection = (link.ssid[0] != '\0' &&
                          strcmp(link.ssid, wardrive_last_connected_ssid) == 0);
    pthread_mutex_unlock(&wardrive_mutex);

    /* FALLBACK ONLY: connected to something wardrive didn't put it on (a
     * trusted saved network, or NetworkManager's own autoconnect finding
     * one) - leave it alone, no matter what's open nearby. This is the
     * whole point of "fallback only" mode. */
    if (link.ssid[0] != '\0' && !on_our_connection) {
        return;
    }

    n = wifi_scan_open(results, WIFI_SCAN_MAX_RESULTS);
    if (n <= 0) {
        return; /* nothing open in range right now */
    }

    best = -1;
    for (i = 0; i < n; i++) {
        if (results[i].signal_percent < WARDRIVE_MIN_SIGNAL_PERCENT) {
            continue;
        }
        if (best < 0 ||
                results[i].signal_percent > results[best].signal_percent) {
            best = i;
        }
    }
    if (best < 0) {
        return; /* nothing strong enough to bother with */
    }

    if (link.ssid[0] != '\0') {
        if (strcmp(link.ssid, results[best].ssid) == 0) {
            return; /* already on the strongest open network - nothing to do */
        }
        if (results[best].signal_percent <
                link.signal_percent + WARDRIVE_SWITCH_MARGIN_PERCENT) {
            return; /* not meaningfully better than what we're already on - avoid flapping */
        }
    }

    snprintf(conn_name, sizeof(conn_name), "%s%s", WARDRIVE_CONN_NAME_PREFIX,
              results[best].ssid);

    if (wifi_connect_open_named(results[best].ssid, conn_name,
                                  err, sizeof(err)) == 0) {
        pthread_mutex_lock(&wardrive_mutex);
        snprintf(wardrive_last_connected_ssid,
                  sizeof(wardrive_last_connected_ssid), "%s",
                  results[best].ssid);
        pthread_mutex_unlock(&wardrive_mutex);

        /* Deletes every wardrive-* profile except the one we're on now -
         * keeps at most one saved profile on the persisted NetworkManager
         * partition no matter how many distinct open networks get caught
         * over weeks/months of roaming. */
        wifi_delete_connections_with_prefix(WARDRIVE_CONN_NAME_PREFIX);
    }
}

static void *wardrive_thread_main(void *arg)
{
    (void)arg;

    for (;;) {
        int enabled;
        struct timespec ts;

        pthread_mutex_lock(&wardrive_mutex);
        if (!wardrive_should_stop) {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += WARDRIVE_CHECK_INTERVAL_SECONDS;
            /* Woken early by wardrive_set_enabled() so a toggle takes
             * effect immediately rather than waiting out the interval. */
            pthread_cond_timedwait(&wardrive_cond, &wardrive_mutex, &ts);
        }
        if (wardrive_should_stop) {
            pthread_mutex_unlock(&wardrive_mutex);
            break;
        }
        enabled = wardrive_enabled;
        pthread_mutex_unlock(&wardrive_mutex);

        if (enabled) {
            wardrive_evaluate();
        }
    }

    return NULL;
}

/* --- Public API --- */

void wardrive_init(void)
{
    wardrive_enabled = load_persisted_state();
    wardrive_should_stop = 0;
    if (pthread_create(&wardrive_tid, NULL, wardrive_thread_main, NULL) == 0) {
        wardrive_thread_running = 1;
    }
}

void wardrive_shutdown(void)
{
    if (!wardrive_thread_running) {
        return;
    }
    pthread_mutex_lock(&wardrive_mutex);
    wardrive_should_stop = 1;
    pthread_cond_signal(&wardrive_cond);
    pthread_mutex_unlock(&wardrive_mutex);
    pthread_join(wardrive_tid, NULL);
    wardrive_thread_running = 0;
}

void wardrive_set_enabled(int enabled)
{
    pthread_mutex_lock(&wardrive_mutex);
    wardrive_enabled = enabled ? 1 : 0;
    pthread_cond_signal(&wardrive_cond);
    pthread_mutex_unlock(&wardrive_mutex);
    persist_state(wardrive_enabled);
}

int wardrive_is_enabled(void)
{
    int v;
    pthread_mutex_lock(&wardrive_mutex);
    v = wardrive_enabled;
    pthread_mutex_unlock(&wardrive_mutex);
    return v;
}

void wardrive_status_line(char *buf, size_t buf_size)
{
    int enabled = wardrive_is_enabled();
    wifi_link_info link;

    if (!enabled) {
        snprintf(buf, buf_size, "wardrive: OFF");
        return;
    }

    if (wifi_get_link_info(&link) == 0 && link.ssid[0] != '\0') {
        int ours;
        pthread_mutex_lock(&wardrive_mutex);
        ours = (strcmp(link.ssid, wardrive_last_connected_ssid) == 0);
        pthread_mutex_unlock(&wardrive_mutex);
        snprintf(buf, buf_size,
                  "wardrive: ON - connected to '%s' (%s, %d%%)", link.ssid,
                  ours ? "open, caught by wardrive" : "trusted network",
                  link.signal_percent);
    } else {
        snprintf(buf, buf_size,
                  "wardrive: ON - no network connected yet");
    }
}

#else /* !__linux__ */

/* No nmcli/NetworkManager on non-Linux - wardrive_init()/_shutdown()/
 * _set_enabled() are no-op static inlines in wardrive.h; only this one
 * needs a real symbol here since it has no header-inline stub. */
int wardrive_is_enabled(void)
{
    return 0;
}

void wardrive_status_line(char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, "wardrive: OFF");
}

#endif /* __linux__ */

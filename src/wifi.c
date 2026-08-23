#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi.h"

#ifdef __linux__

#include <unistd.h>
#include <sys/wait.h>

/*
 * run_nmcli - fork()+execvp() argv[0] (almost always "nmcli" - see
 * wifi_connect()'s own comment for the one exception, "sudo", which
 * then execs nmcli itself as ITS argv[1]) with the given NULL-
 * terminated argv, capturing combined stdout+stderr into out_buf
 * (NUL-terminated, truncated if it doesn't fit - pass NULL/0 to
 * discard output entirely, e.g. for wifi_has_connectivity()
 * piggy-backing on this same helper isn't needed there, but
 * scan/connect both want it).
 * Deliberately no shell involved at all - see wifi.h's SECURITY NOTE.
 *
 * Returns nmcli's exit status (0 = success) on a normal exit, or -1 if
 * the fork/pipe itself failed or the child didn't exit normally.
 */
static int run_nmcli(char *const argv[], char *out_buf, size_t out_buf_size)
{
    int pipefd[2];
    pid_t pid;
    int status;
    size_t have = 0;

    if (out_buf != NULL && out_buf_size > 0) {
        out_buf[0] = '\0';
    }

    if (pipe(pipefd) != 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv); /* argv[0] IS the executable to run -
            almost always "nmcli", but wifi_connect() also passes
            "sudo" (nmcli as ITS argv[1]) for the one operation that
            genuinely needs elevated NetworkManager permissions - see
            its own comment. Previously hardcoded to "nmcli" here
            regardless of argv[0]'s actual value, which would have
            silently made a "sudo" prefix a no-op (execvp'd "nmcli"
            directly anyway, ignoring argv[0] entirely, still running
            unprivileged) rather than genuinely elevating anything. */
        _exit(127); /* execvp only returns on failure */
    }

    /* parent */
    close(pipefd[1]);
    if (out_buf != NULL && out_buf_size > 0) {
        for (;;) {
            ssize_t n = read(pipefd[0], out_buf + have,
                              out_buf_size - 1 - have);
            if (n <= 0) {
                break;
            }
            have += (size_t)n;
            if (have >= out_buf_size - 1) {
                break;
            }
        }
        out_buf[have] = '\0';
    } else {
        char discard[256];
        while (read(pipefd[0], discard, sizeof(discard)) > 0) {
            /* drain and discard */
        }
    }
    close(pipefd[0]);

    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int wifi_scan(wifi_network *out_networks, int max_results)
{
    char buf[8192];
    char *line;
    char *saveptr = NULL;
    int count = 0;
    char *argv[] = { (char *)"nmcli", (char *)"-t", (char *)"-f",
                      (char *)"SSID,SECURITY", (char *)"device",
                      (char *)"wifi", (char *)"list", NULL };

    if (out_networks == NULL || max_results <= 0) {
        return -1;
    }

    if (run_nmcli(argv, buf, sizeof(buf)) < 0) {
        return -1;
    }

    line = strtok_r(buf, "\n", &saveptr);
    while (line != NULL && count < max_results) {
        /* nmcli's terse (-t) output is colon-delimited, with a
         * literal ':' inside a field escaped as '\:' - the only
         * escape this format uses. Split on the first UNESCAPED
         * colon to separate SSID from SECURITY. */
        char ssid[WIFI_SSID_MAX];
        size_t si = 0;
        char *p = line;
        int secured;

        while (*p != '\0' && si < sizeof(ssid) - 1) {
            if (p[0] == '\\' && p[1] == ':') {
                ssid[si++] = ':';
                p += 2;
            } else if (*p == ':') {
                p++; /* now points at the start of the SECURITY field */
                break;
            } else {
                ssid[si++] = *p++;
            }
        }
        ssid[si] = '\0';

        /* nmcli prints "--" in the SECURITY column for an open
         * network with no security at all - anything else (WPA1,
         * WPA2, WPA3, WEP, combinations) means a password is needed. */
        secured = (strstr(p, "--") == NULL);

        if (si > 0) {
            int dup = 0;
            int i;
            for (i = 0; i < count; i++) {
                if (strcmp(out_networks[i].ssid, ssid) == 0) {
                    dup = 1;
                    break;
                }
            }
            if (!dup) {
                snprintf(out_networks[count].ssid,
                          sizeof(out_networks[count].ssid), "%s", ssid);
                out_networks[count].secured = secured;
                count++;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    return count;
}

int wifi_connect(const char *ssid, const char *password,
                  char *out_error, size_t out_error_size)
{
    char output[2048];
    int rc;

    if (ssid == NULL || ssid[0] == '\0') {
        return -1;
    }

    /* REAL BUG FOUND AND FIXED (2026-08-23): this service runs as an
     * unprivileged user (see securelink-alpha.service/-bravo.service's
     * User=connor), and plain `nmcli device wifi connect` for an SSID
     * with no existing saved connection profile requires NetworkManager
     * to ADD a brand new system-wide profile, not just activate one
     * that's already there - a genuinely different, more privileged
     * polkit action than scanning or activating an already-known
     * connection (which is why wifi_scan()/wifi_has_connectivity()
     * above and the already-known BDH-public profile's own automatic
     * boot-time activation both work fine unprivileged, while this one
     * call never did). Confirmed directly via journalctl -u
     * NetworkManager: every real Ctrl+W connect attempt failed with
     * `op="connection-add-activate" ... uid=1000 result="fail"
     * reason="Not authorized to control networking."` - meaning this
     * whole feature silently failed on every genuinely new network,
     * every time, in the real deployed service - not a timeout, not
     * specific to any one SSID. `sudo` (already relies on this
     * project's own established NOPASSWD sudoers entry, same as every
     * other elevated call this project makes - never an interactive
     * password prompt) resolves it: confirmed live, the identical
     * command succeeded immediately (well under 10 seconds, full
     * association + DHCP) the moment it ran as uid=0 instead of 1000. */
    if (password != NULL && password[0] != '\0') {
        char *argv[] = { (char *)"sudo", (char *)"nmcli", (char *)"device",
                          (char *)"wifi", (char *)"connect", (char *)ssid,
                          (char *)"password", (char *)password, NULL };
        rc = run_nmcli(argv, output, sizeof(output));
    } else {
        char *argv[] = { (char *)"sudo", (char *)"nmcli", (char *)"device",
                          (char *)"wifi", (char *)"connect", (char *)ssid,
                          NULL };
        rc = run_nmcli(argv, output, sizeof(output));
    }

    if (rc != 0 && out_error != NULL && out_error_size > 0) {
        snprintf(out_error, out_error_size, "%s", output);
    }

    return rc == 0 ? 0 : -1;
}

int wifi_has_connectivity(void)
{
    char output[64];
    char *argv[] = { (char *)"nmcli", (char *)"networking",
                      (char *)"connectivity", NULL };

    if (run_nmcli(argv, output, sizeof(output)) < 0) {
        return 0;
    }
    return strstr(output, "full") != NULL;
}

int wifi_get_link_info(wifi_link_info *out_info)
{
    char buf[4096];
    char *line;
    char *saveptr = NULL;
    char *argv[] = { (char *)"nmcli", (char *)"-t", (char *)"-f",
                      (char *)"active,ssid,signal,rate", (char *)"device",
                      (char *)"wifi", (char *)"list", NULL };

    if (out_info == NULL) {
        return -1;
    }
    out_info->ssid[0] = '\0';
    out_info->signal_percent = -1;
    out_info->rate[0] = '\0';

    if (run_nmcli(argv, buf, sizeof(buf)) < 0) {
        return -1;
    }

    line = strtok_r(buf, "\n", &saveptr);
    while (line != NULL) {
        /* Only the "active:...(yes)" row (there's at most one) is the
         * one we want - every other row is a different visible AP for
         * the same or a different SSID, not this device's own link. */
        if (strncmp(line, "yes:", 4) == 0) {
            /* Same escaped-colon-aware SSID parsing as wifi_scan() -
             * an SSID can legitimately contain a literal ':', escaped
             * as '\:' in nmcli's terse output. */
            char *p = line + 4;
            size_t si = 0;

            while (*p != '\0' && si < sizeof(out_info->ssid) - 1) {
                if (p[0] == '\\' && p[1] == ':') {
                    out_info->ssid[si++] = ':';
                    p += 2;
                } else if (*p == ':') {
                    p++; /* now at the start of "signal:rate" */
                    break;
                } else {
                    out_info->ssid[si++] = *p++;
                }
            }
            out_info->ssid[si] = '\0';

            out_info->signal_percent = atoi(p);
            {
                char *rate_start = strchr(p, ':');
                if (rate_start != NULL) {
                    rate_start++;
                    snprintf(out_info->rate, sizeof(out_info->rate), "%s",
                              rate_start);
                }
            }
            return 0;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    return -1; /* no active WiFi connection right now */
}

#else /* !__linux__ */

/* This project's Windows dev machine has no NetworkManager/nmcli, and
 * the WiFi setup screen is a Linux/ncurses-only UI feature (see
 * ui.c) - these stubs exist only so callers can link on either
 * platform without #ifdef guards at every call site, matching
 * hw_expansion.h's established precedent. */

int wifi_scan(wifi_network *out_networks, int max_results)
{
    (void)out_networks;
    (void)max_results;
    return -1;
}

int wifi_connect(const char *ssid, const char *password,
                  char *out_error, size_t out_error_size)
{
    (void)ssid;
    (void)password;
    if (out_error != NULL && out_error_size > 0) {
        out_error[0] = '\0';
    }
    return -1;
}

int wifi_has_connectivity(void)
{
    return 1; /* assume yes - this path is never actually exercised
               * (no WiFi setup screen exists on non-Linux, see ui.c) */
}

int wifi_get_link_info(wifi_link_info *out_info)
{
    if (out_info != NULL) {
        out_info->ssid[0] = '\0';
        out_info->signal_percent = -1;
        out_info->rate[0] = '\0';
    }
    return -1; /* no OLED/WiFi metrics display exists on non-Linux */
}

#endif /* __linux__ */

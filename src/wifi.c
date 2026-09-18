#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi.h"

#ifdef __linux__

#include <unistd.h>
#include <sys/wait.h>

/* run_nmcli - fork()+execvp() argv (no shell, see wifi.h SECURITY NOTE), capturing stdout+stderr into out_buf; returns nmcli's exit status or -1. See COMMENT_ARCHIVE.md for a real bug this fixed. */
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
        execvp(argv[0], argv); /* argv[0] is the executable - see COMMENT_ARCHIVE.md for a real bug where this was hardcoded instead */
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

/* `nmcli device wifi rescan` only requests a scan; this is how long we wait for it to settle. See COMMENT_ARCHIVE.md. */
#define WIFI_SCAN_SETTLE_SECONDS 4

/* parse_escaped_ssid_field - parses one colon-delimited, "\:"-escaped SSID field at *cursor into out_ssid, advancing *cursor past it. Fuzz-tested (build/wifi_fuzz.c). See COMMENT_ARCHIVE.md. */
static void parse_escaped_ssid_field(const char **cursor, char *out_ssid,
                                       size_t out_size)
{
    const char *p = *cursor;
    size_t si = 0;

    if (out_size == 0) {
        /* Defensive only - no real call site passes 0. */
        *cursor = p;
        return;
    }

    while (*p != '\0' && si < out_size - 1) {
        if (p[0] == '\\' && p[1] == ':') {
            out_ssid[si++] = ':';
            p += 2;
        } else if (*p == ':') {
            p++; /* now points at the start of the next field */
            break;
        } else {
            out_ssid[si++] = *p++;
        }
    }
    out_ssid[si] = '\0';
    *cursor = p;
}

int wifi_scan(wifi_network *out_networks, int max_results)
{
    char buf[8192];
    char *line;
    char *saveptr = NULL;
    int count = 0;
    char *rescan_argv[] = { (char *)"sudo", (char *)"nmcli", (char *)"device",
                              (char *)"wifi", (char *)"rescan", NULL };
    char *argv[] = { (char *)"nmcli", (char *)"-t", (char *)"-f",
                      (char *)"SSID,SECURITY", (char *)"device",
                      (char *)"wifi", (char *)"list", NULL };

    if (out_networks == NULL || max_results <= 0) {
        return -1;
    }

    /* Force a fresh rescan (sudo, best-effort) before reading results so every Ctrl+W scan is current. See COMMENT_ARCHIVE.md for two real bugs fixed here. */
    run_nmcli(rescan_argv, NULL, 0);
    sleep(WIFI_SCAN_SETTLE_SECONDS);

    if (run_nmcli(argv, buf, sizeof(buf)) < 0) {
        return -1;
    }

    line = strtok_r(buf, "\n", &saveptr);
    while (line != NULL && count < max_results) {
        /* nmcli's terse (-t) output is colon-delimited; split on the first unescaped colon to separate SSID from SECURITY. */
        char ssid[WIFI_SSID_MAX];
        const char *p = line;
        int secured;
        size_t si;

        parse_escaped_ssid_field(&p, ssid, sizeof(ssid));
        si = strlen(ssid);

        /* Terse mode's open-network convention differs from human-readable mode. See COMMENT_ARCHIVE.md for the bug this fixed. */
        secured = (p[0] != '\0');

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

    /* Connecting needs sudo and a fresh rescan first to avoid a stale-cache failure. See COMMENT_ARCHIVE.md for three real bugs fixed here. */
    {
        char *rescan_argv[] = { (char *)"sudo", (char *)"nmcli", (char *)"device",
                                  (char *)"wifi", (char *)"rescan", NULL };
        run_nmcli(rescan_argv, NULL, 0); /* best-effort - ignore rc */
        sleep(2); /* let the radio finish the scan before connecting */
    }

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
        /* Only the "active:...(yes)" row (at most one) is this device's own link. */
        if (strncmp(line, "yes:", 4) == 0) {
            const char *p = line + 4;

            parse_escaped_ssid_field(&p, out_info->ssid,
                                       sizeof(out_info->ssid));

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

/* No nmcli on non-Linux (WiFi setup screen is Linux/ncurses-only, see ui.c); these stubs let callers link unconditionally. */

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
    return 1; /* assume yes - never exercised on non-Linux */
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

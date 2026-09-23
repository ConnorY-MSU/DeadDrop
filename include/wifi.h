#ifndef WIFI_H
#define WIFI_H

#include <stddef.h>

/* wifi - thin wrapper around `nmcli` for the ncurses UI's WiFi setup screen. Linux/NetworkManager-only, see wifi.c for the non-Linux stub. */
/* SECURITY NOTE: every nmcli call goes through fork()+execvp() with an explicit argv, never system()/popen() - no shell, no injection surface. */

#define WIFI_SSID_MAX 64
#define WIFI_SCAN_MAX_RESULTS 32

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int secured; /* 1 if the network needs a password, 0 if open */
} wifi_network;

/* wifi_scan - run `nmcli device wifi list`, parse into out_networks (deduplicated). Returns count found, or -1 if nmcli couldn't run. */
int wifi_scan(wifi_network *out_networks, int max_results);

/* wifi_connect - connect to `ssid` with `password` (NULL/empty for open). Returns 0/-1; on failure out_error is filled with nmcli's output. */
int wifi_connect(const char *ssid, const char *password,
                  char *out_error, size_t out_error_size);

/* wifi_has_connectivity - checks (`nmcli networking connectivity`) whether this device has any usable network path. Returns 1/0. */
int wifi_has_connectivity(void);

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int signal_percent;  /* 0-100, or -1 if unknown */
    char rate[32];        /* nmcli's own text, e.g. "195 Mbit/s" - unit varies, only ever displayed */
} wifi_link_info;

/* wifi_get_link_info - details of the active WiFi connection for the OLED metrics display. Returns 0 and fills out_info, or -1 (blank fields) if none. */
int wifi_get_link_info(wifi_link_info *out_info);

/* --- Open-network scan/connect/prune, for wardrive.c only --- */
/* Deliberately a separate result type and scan/connect path from wifi_network/wifi_scan()/wifi_connect() above, not a shared one: wardrive.c's own parsing changes should never risk the already fuzz-tested Ctrl+W scan/connect flow. See COMMENT_ARCHIVE.md. */

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int signal_percent; /* 0-100; duplicate SSIDs (e.g. a mesh AP seen on multiple BSSIDs) are collapsed to their strongest reading */
} wifi_open_network;

/* wifi_scan_open - like wifi_scan(), but OPEN networks only, with signal strength, unsorted. Returns count found (0 if none), or -1 if nmcli couldn't run. */
int wifi_scan_open(wifi_open_network *out_networks, int max_results);

/* wifi_connect_open_named - connect to open network `ssid` (no password), saving the resulting NetworkManager profile as `conn_name` instead of nmcli's default (the SSID itself). Lets wardrive.c recognize and prune its own connections later without ever touching one it didn't create. */
int wifi_connect_open_named(const char *ssid, const char *conn_name,
                              char *out_error, size_t out_error_size);

/* wifi_delete_connections_with_prefix - best-effort delete of every saved, currently-INACTIVE connection profile whose name starts with `prefix`. Never touches the active connection even if its name matches. For wardrive.c's own cleanup, so roaming across many open networks over weeks/months doesn't leave unbounded saved profiles behind on the persisted NetworkManager partition. */
void wifi_delete_connections_with_prefix(const char *prefix);

#endif /* WIFI_H */

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

#endif /* WIFI_H */

#ifndef WIFI_H
#define WIFI_H

#include <stddef.h>

/*
 * wifi - thin wrapper around `nmcli`, used by the ncurses UI's WiFi
 * setup screen (Week 4 Days 2-3 Part H, see
 * Field WiFi and Network Resilience Concepts.md). Linux/NetworkManager-
 * only - see wifi.c for the non-Linux stub. This module only ever
 * shells out to nmcli and parses its output; it has no knowledge of
 * ncurses, sockets, or the protocol layer, matching lock.c's precedent
 * of small, decoupled modules.
 *
 * SECURITY NOTE, worth stating explicitly: every nmcli invocation here
 * goes through fork()+execvp() with an explicit argv array, never
 * system()/popen() with a shell-interpreted command string. An SSID
 * (attacker-influenceable - it's whatever a nearby access point
 * broadcasts) and a WiFi password (typed by whoever is at the device)
 * are both real untrusted input; passing them as separate execvp()
 * argv elements means the shell never sees or interprets them at all,
 * so there is no shell-metacharacter injection surface to reason about
 * here, by construction rather than by careful escaping.
 */

#define WIFI_SSID_MAX 64
#define WIFI_SCAN_MAX_RESULTS 32

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int secured; /* 1 if the network needs a password, 0 if open */
} wifi_network;

/*
 * wifi_scan - run `nmcli device wifi list`, parse into out_networks
 * (caller-owned array of at least max_results entries). Deduplicates
 * repeated SSIDs (the same network can show up once per visible
 * access point). Returns the number of networks found (0 is a valid,
 * real result - no networks in range), or -1 if nmcli itself couldn't
 * be run at all.
 */
int wifi_scan(wifi_network *out_networks, int max_results);

/*
 * wifi_connect - connect to `ssid`, with `password` (pass NULL or an
 * empty string for an open network). Returns 0 on success, -1 on
 * failure. On failure, out_error (if non-NULL) is filled with nmcli's
 * own output (truncated to out_error_size) - a wrong password and an
 * out-of-range network fail differently, and nmcli's own message is
 * more specific and more honest than this module guessing at one.
 */
int wifi_connect(const char *ssid, const char *password,
                  char *out_error, size_t out_error_size);

/*
 * wifi_has_connectivity - quick check (`nmcli networking
 * connectivity`) for whether this device currently has any usable
 * network path at all. Returns 1 if yes, 0 if no or unknown.
 */
int wifi_has_connectivity(void);

typedef struct {
    char ssid[WIFI_SSID_MAX];
    int signal_percent;  /* 0-100, or -1 if unknown */
    char rate[32];        /* nmcli's own text, e.g. "195 Mbit/s" - kept
                              as a string rather than parsed to a number,
                              since it's link rate not a fixed unit
                              (could be Mbit/s or Gbit/s) and this is
                              only ever displayed, never computed on */
} wifi_link_info;

/*
 * wifi_get_link_info - details of the CURRENTLY ACTIVE WiFi connection
 * (the "active" marker on `nmcli device wifi list`'s own output - the
 * same command wifi_scan() already uses, filtered differently), for the
 * OLED's background metrics display (see ui.c). Fills out_info and
 * returns 0 if there IS an active WiFi connection right now; returns -1
 * (out_info's fields left blank) if there isn't one - e.g. this device
 * is on Ethernet only, or genuinely offline. Real field format
 * (`active:ssid:signal:rate`) confirmed against actual nmcli output on
 * this project's own deployed hardware, not assumed from documentation.
 */
int wifi_get_link_info(wifi_link_info *out_info);

#endif /* WIFI_H */

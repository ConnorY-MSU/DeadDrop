#ifndef WARDRIVE_H
#define WARDRIVE_H

/* wardrive - optional background mode: while ON, automatically connects to
 * the strongest OPEN WiFi network in range whenever no trusted/known
 * network is available, so a mobile device stays reachable out in the
 * field. FALLBACK ONLY by design: it never abandons an already-up
 * trusted/known connection just because a stronger open network shows up -
 * see wardrive.c. OFF by default; toggled via "/wardrive on|off"; the
 * on/off state persists across reboots (stored under ~/.deaddrop, the same
 * persisted bind-mount msglog.c uses). Linux/NetworkManager-only, see
 * wardrive.c for the non-Linux stub. */

/* wardrive_init - load the persisted on/off state and start the background
 * scan/connect thread. Call once at startup, alongside hw_tts_init(). Never
 * fatal to the caller - if the thread can't start, wardrive mode simply
 * never activates. */
#ifdef __linux__
void wardrive_init(void);
#else
static inline void wardrive_init(void) { }
#endif

/* wardrive_shutdown - stop the background thread. Call once at the end of
 * main(), alongside hw_tts_shutdown(). */
#ifdef __linux__
void wardrive_shutdown(void);
#else
static inline void wardrive_shutdown(void) { }
#endif

/* wardrive_set_enabled - turn wardrive mode on/off; persists immediately so
 * it survives a reboot, and wakes the background thread right away rather
 * than waiting out its own check interval. */
#ifdef __linux__
void wardrive_set_enabled(int enabled);
#else
static inline void wardrive_set_enabled(int enabled) { (void)enabled; }
#endif

/* wardrive_is_enabled - current on/off state. Cheap (no subprocess calls),
 * safe to call from anywhere. */
int wardrive_is_enabled(void);

/* wardrive_status_line - a human-readable one-line status for the
 * "/wardrive" bare-command report, e.g. "wardrive: OFF" or "wardrive: ON -
 * connected to 'CafeWifi' (open, caught by wardrive, 63%)". Runs a
 * subprocess call (nmcli) on Linux - same rule as the rest of wifi.c:
 * never call this while holding ui_mutex. */
void wardrive_status_line(char *buf, size_t buf_size);

#endif /* WARDRIVE_H */

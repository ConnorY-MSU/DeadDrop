#ifndef HW_EXPANSION_H
#define HW_EXPANSION_H

#include <stdint.h>

/*
 * hw_expansion - I2C control for the Freenove FNK0100 case's onboard
 * expansion board (RGB LEDs + case fans), Week 4 physical-build addition.
 *
 * Hardware: a Nuvoton MS51FB9AE microcontroller on the case's own PCB,
 * exposed to the Raspberry Pi as an I2C slave at address 0x21 on bus 1
 * (/dev/i2c-1). The register map below was NOT guessed or reverse
 * engineered - it's taken directly from Freenove's own published
 * reference implementation (api_expansion.py, in
 * github.com/Freenove/Freenove_Computer_Case_Kit_for_Raspberry_Pi),
 * confirmed against their source rather than assumed from a product
 * description.
 *
 * IMPORTANT STATUS NOTE: this module is Linux-only by nature (Linux's
 * i2c-dev ioctl interface has no Windows equivalent at all - unlike the
 * portable socket code elsewhere in this project, there's no dev-machine
 * loopback-style test available here). It has been written carefully
 * against the real, verified register protocol, but it has NOT been
 * compiled or run against real hardware - the Pi doesn't have an OS
 * installed yet (Week 4 Day 1 hasn't happened). Treat this as a
 * reviewed-on-paper prototype, not a tested component, until it's
 * actually been run on the real Pi with the real board attached. Do not
 * report this as "working" anywhere (TESTING.md, README, etc.) until
 * that real verification has happened - the same discipline this
 * project has applied to every other claim so far.
 */

/* RGB LED "mode" register (0x03) values, per the board's own firmware -
 * mode must be MANUAL_RGB for hw_expansion_set_status_color() to take
 * visible effect; the board's default/other modes (breathing, rainbow,
 * temperature-following) would override or ignore a static color write. */
typedef enum {
    HW_LED_MODE_OFF          = 0,
    HW_LED_MODE_MANUAL_RGB   = 1,
    HW_LED_MODE_FOLLOWING    = 2,
    HW_LED_MODE_BREATHING    = 3,
    HW_LED_MODE_RAINBOW      = 4
} hw_led_mode;

/* Connection status this project cares about - the actual RGB values
 * for each meaning live in one place (hw_expansion.c), not scattered
 * across every call site that wants to report a status change. */
typedef enum {
    HW_STATUS_DISCONNECTED,  /* red     - no active session */
    HW_STATUS_CONNECTING,    /* amber   - TCP/TLS handshake in progress,
                               * or a reconnect-with-backoff retry pending */
    HW_STATUS_CONNECTED,     /* green   - live mTLS session established */
    HW_STATUS_ALERT           /* magenta - an unacknowledged incoming
                               * message is pending (see
                               * ui_notify_message_pending() in ui.h) -
                               * deliberately distinct from the three
                               * connection-state colors above so it can
                               * never be mistaken for one, and matches
                               * the same magenta used for the ncurses
                               * UI's own "cyberpunk neon" palette. */
} hw_connection_status;

/*
 * hw_expansion_open - open /dev/i2c-1 and address the expansion board.
 *
 * Returns a file descriptor to pass into the other hw_expansion_*
 * calls, or -1 on any failure (bus not present, board not responding,
 * permission denied, etc.). Hardware absence must be treated as
 * non-fatal by every caller - this project's core protocol
 * functionality does not, and must never, depend on this hardware being
 * present or working. A dev/test machine or a Pi without this specific
 * case attached should keep working identically with this returning -1.
 */

/*
 * hw_expansion_set_led_mode - write REG_LED_MODE (0x03).
 *
 * Call once at startup with HW_LED_MODE_MANUAL_RGB before using
 * hw_expansion_set_status_color() - see the mode note above. fd < 0 is
 * silently a no-op (see hw_expansion_open()'s contract).
 */

/*
 * hw_expansion_set_status_color - set every case LED to the color
 * associated with the given connection status (REG_LED_ALL, 0x02).
 * fd < 0 is silently a no-op.
 */

/*
 * hw_expansion_close - release the I2C file descriptor. Safe to call
 * with fd < 0 (no-op).
 */

#ifdef __linux__

int hw_expansion_open(void);
void hw_expansion_set_led_mode(int fd, hw_led_mode mode);
void hw_expansion_set_status_color(int fd, hw_connection_status status);
void hw_expansion_close(int fd);

#else

/* Non-Linux build (this project's Windows dev machine, until Week 4
 * hardware exists): harmless no-op stubs, defined right here rather
 * than in a separate .c file, so client.c/server.c can call
 * hw_expansion_*() unconditionally without every call site needing its
 * own #ifdef __linux__ guard - the platform branch lives in exactly one
 * place (this header) instead of being scattered through the files that
 * use it. static inline: each including .c file gets its own definition,
 * no separate compilation unit or linking step needed, and an unused one
 * (e.g. in a file that includes this header but never calls a given
 * function) won't produce an unused-function warning the way a plain
 * `static` function would. */
static inline int hw_expansion_open(void) { return -1; }
static inline void hw_expansion_set_led_mode(int fd, hw_led_mode mode)
    { (void)fd; (void)mode; }
static inline void hw_expansion_set_status_color(int fd, hw_connection_status status)
    { (void)fd; (void)status; }
static inline void hw_expansion_close(int fd) { (void)fd; }

#endif /* __linux__ */

#endif /* HW_EXPANSION_H */

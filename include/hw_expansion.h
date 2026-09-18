#ifndef HW_EXPANSION_H
#define HW_EXPANSION_H

#include <stdint.h>

/* hw_expansion - I2C control for the FNK0100 case's expansion board (RGB LEDs + fans). Linux-only, not yet verified on real hardware. See COMMENT_ARCHIVE.md. */

/* REG_LED_MODE (0x03) values. Must be MANUAL_RGB for hw_expansion_set_status_color() to have visible effect. */
typedef enum {
    HW_LED_MODE_OFF          = 0,
    HW_LED_MODE_MANUAL_RGB   = 1,
    HW_LED_MODE_FOLLOWING    = 2,
    HW_LED_MODE_BREATHING    = 3,
    HW_LED_MODE_RAINBOW      = 4
} hw_led_mode;

/* Connection status colors (RGB values in hw_expansion.c); MSG_* flash alternating with the base color. See COMMENT_ARCHIVE.md for the 2026-08-22 redesign. */
typedef enum {
    HW_STATUS_DISCONNECTED,       /* red    - no active session */
    HW_STATUS_CONNECTING,         /* amber  - handshake or reconnect pending */
    HW_STATUS_CONNECTED,          /* green  - live session, no unread message */
    HW_STATUS_MSG_CONNECTED,      /* blue   - message pending, link up (flashes w/ green) */
    HW_STATUS_MSG_DISCONNECTED    /* orange - message pending, link down (flashes w/ red) */
} hw_connection_status;

/* hw_expansion_open - open /dev/i2c-1 and address the expansion board. Returns an fd, or -1 (must be treated as non-fatal by callers). */

/* hw_expansion_set_led_mode - write REG_LED_MODE; call once at startup with HW_LED_MODE_MANUAL_RGB. fd < 0 is a no-op. */

/* hw_expansion_set_status_color - set every case LED per connection status (REG_LED_ALL, 0x02). fd < 0 is a no-op. */

/* hw_expansion_close - release the I2C file descriptor. Safe with fd < 0 (no-op). */

#ifdef __linux__

int hw_expansion_open(void);
void hw_expansion_set_led_mode(int fd, hw_led_mode mode);
void hw_expansion_set_status_color(int fd, hw_connection_status status);
void hw_expansion_close(int fd);

#else

/* Non-Linux build: no-op stubs so client.c/server.c can call hw_expansion_*() unconditionally without their own #ifdef guard. */
static inline int hw_expansion_open(void) { return -1; }
static inline void hw_expansion_set_led_mode(int fd, hw_led_mode mode)
    { (void)fd; (void)mode; }
static inline void hw_expansion_set_status_color(int fd, hw_connection_status status)
    { (void)fd; (void)status; }
static inline void hw_expansion_close(int fd) { (void)fd; }

#endif /* __linux__ */

#endif /* HW_EXPANSION_H */

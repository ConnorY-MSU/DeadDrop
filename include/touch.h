#ifndef TOUCH_H
#define TOUCH_H

/*
 * touch - reads raw touchscreen tap events from Linux evdev
 * (/dev/input/eventN), for the ncurses UI's touch features (Week 4
 * Days 2-3, "Selection + wake" scope - see ui.c's touch block
 * comment). Linux-only, no ncurses dependency - this module only
 * knows about raw evdev events and normalized panel coordinates,
 * matching wifi.c/lock.c's precedent of small, decoupled modules.
 *
 * DEVICE DISCOVERY: deliberately enumerates /dev/input/event* and
 * matches by CAPABILITY (ABS_X + ABS_Y + INPUT_PROP_DIRECT), never a
 * hardcoded device path - confirmed via `cat /proc/bus/input/devices`
 * and `evtest` against the real FNK0100 hardware that the touch panel
 * is an ft5x06 controller at /dev/input/event1, but the exact event
 * number is not guaranteed stable across boots or between two
 * otherwise-identical Pis - the same lesson already learned the hard
 * way from this project's DSI-vs-HDMI fb0/fb1 framebuffer-numbering
 * surprise (see TESTING.md).
 *
 * PROTOCOL: uses the simple single-touch protocol (ABS_X/ABS_Y +
 * BTN_TOUCH), which the real hardware reports alongside the full
 * multitouch protocol - sufficient for tap-to-select, no need for
 * this project to track multiple simultaneous touch points.
 */

typedef struct {
    float x; /* 0.0 (left) .. 1.0 (right) */
    float y; /* 0.0 (top) .. 1.0 (bottom) */
} touch_point;

/*
 * touch_open - find and open the touchscreen input device. Returns a
 * file descriptor to pass to touch_read_tap()/touch_close(), or -1 if
 * none was found (no touchscreen attached, insufficient permission,
 * or not running on Linux) - callers must treat that as non-fatal,
 * same contract as hw_expansion_open()/hw_oled_open().
 */
int touch_open(void);

/*
 * touch_read_tap - block for up to timeout_ms waiting for a touch-down
 * event, filling out_point with its normalized position at the moment
 * of touch-down. Returns 1 if a tap was read, 0 on timeout, -1 on a
 * real error (device gone - e.g. unplugged).
 */
int touch_read_tap(int fd, touch_point *out_point, int timeout_ms);

void touch_close(int fd);

#endif /* TOUCH_H */

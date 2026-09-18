#ifndef TOUCH_H
#define TOUCH_H

/* touch - reads raw touchscreen tap events from Linux evdev for the ncurses UI. Finds the device by capability, not a hardcoded path. See COMMENT_ARCHIVE.md. */

typedef struct {
    float x; /* 0.0 (left) .. 1.0 (right) */
    float y; /* 0.0 (top) .. 1.0 (bottom) */
} touch_point;

/* touch_open - find and open the touchscreen input device. Returns an fd, or -1 if none found (non-fatal, same contract as hw_oled_open()). */
int touch_open(void);

/* touch_read_tap - block up to timeout_ms for a touch-down event, filling out_point with its normalized position. Returns 1/0/-1. */
int touch_read_tap(int fd, touch_point *out_point, int timeout_ms);

void touch_close(int fd);

#endif /* TOUCH_H */

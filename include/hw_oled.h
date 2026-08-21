#ifndef HW_OLED_H
#define HW_OLED_H

/*
 * hw_oled - native C driver for the FNK0100 case's SSD1306-compatible
 * 128x64 monochrome OLED (I2C address 0x3C, bus 1 - confirmed from
 * Freenove's own api_oled.py, not guessed). Week 4 physical-build
 * addition, same status as hw_expansion.h: written against real,
 * sourced references (the SSD1306 init sequence and the embedded font
 * in hw_oled_font.h both traced to Adafruit's own MIT-licensed
 * Adafruit_SSD1306/Adafruit-GFX-Library source, not reconstructed from
 * memory), but NOT yet compiled or run against real hardware - see
 * hw_expansion.h's fuller status note, which applies identically here.
 *
 * Text-only API, deliberately - "display when a new message comes
 * through" is this project's actual requirement, not general graphics,
 * so this doesn't implement arbitrary pixel/line drawing.
 */

#define HW_OLED_WIDTH   128
#define HW_OLED_HEIGHT  64
#define HW_OLED_LINES   8   /* 64px / 8px per text line (7px font + 1px gap) */
#define HW_OLED_COLS    21  /* 128px / 6px per char (5px font + 1px gap) */

/*
 * hw_oled_open - open /dev/i2c-1, address the display, run the SSD1306
 * init sequence, and blank the screen.
 *
 * Returns a file descriptor to pass into the other hw_oled_* calls, or
 * -1 on any failure. Hardware absence must be treated as non-fatal by
 * every caller - same contract as hw_expansion_open().
 */

/*
 * hw_oled_clear - clear the in-memory framebuffer (does not itself
 * touch the physical display - call hw_oled_display() afterward to
 * flush the cleared state to screen). fd < 0 is a no-op.
 */

/*
 * hw_oled_draw_text - draw one line of text (up to HW_OLED_COLS
 * characters; longer input is truncated, not wrapped) into the
 * in-memory framebuffer at the given line (0 to HW_OLED_LINES-1).
 * Clears the rest of that line first, so a shorter string correctly
 * overwrites a longer one previously drawn on the same line - callers
 * don't need to clear before every call. Does not itself touch the
 * physical display - call hw_oled_display() to flush. fd < 0 is a
 * no-op; an out-of-range line or a NULL text pointer is also a no-op.
 */

/*
 * hw_oled_display - push the entire in-memory framebuffer to the
 * physical display over I2C. fd < 0 is a no-op.
 */

/*
 * hw_oled_close - release the I2C file descriptor. Safe with fd < 0.
 */

#ifdef __linux__

int hw_oled_open(void);
void hw_oled_clear(int fd);
void hw_oled_draw_text(int fd, int line, const char *text);
void hw_oled_display(int fd);
void hw_oled_close(int fd);

#else

/* Non-Linux build: harmless no-op stubs - see hw_expansion.h's matching
 * comment for the full rationale (one platform branch, here, instead of
 * scattered #ifdefs at every call site). */
static inline int hw_oled_open(void) { return -1; }
static inline void hw_oled_clear(int fd) { (void)fd; }
static inline void hw_oled_draw_text(int fd, int line, const char *text)
    { (void)fd; (void)line; (void)text; }
static inline void hw_oled_display(int fd) { (void)fd; }
static inline void hw_oled_close(int fd) { (void)fd; }

#endif /* __linux__ */

#endif /* HW_OLED_H */

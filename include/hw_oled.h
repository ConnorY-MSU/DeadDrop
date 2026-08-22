#ifndef HW_OLED_H
#define HW_OLED_H

/*
 * hw_oled - native C driver for the FNK0100 case's SSD1306-compatible
 * 128x64 monochrome OLED (I2C address 0x3C, bus 1 - confirmed from
 * Freenove's own api_oled.py, not guessed). Week 4 physical-build
 * addition, written against real, sourced references (the SSD1306 init
 * sequence and the embedded font in hw_oled_font.h both traced to
 * Adafruit's own MIT-licensed Adafruit_SSD1306/Adafruit-GFX-Library
 * source, not reconstructed from memory). Confirmed working on real
 * hardware, both units, 2026-08-21 - see TESTING.md.
 *
 * DISPLAY HIERARCHY - explicit, not incidental: this 128x64 OLED is
 * the SECONDARY display. The FNK0100's 4.3" DSI touchscreen (driven by
 * the real ncurses UI, see ui.h) is the PRIMARY display - full status
 * bar, full scrolling message history, the actual compose line. This
 * OLED exists purely for small, glanceable, at-a-distance signals (a
 * brief "new message" preview, a couple of short status lines) that
 * don't require walking up to and reading the touchscreen - it is
 * never meant to duplicate or substitute for the primary UI's full
 * content, and callers should keep whatever they draw here short and
 * secondary in nature (the 21-character-wide preview used elsewhere in
 * this codebase is the right scale to aim for). Text-only API,
 * deliberately - "brief glanceable notification," not general graphics,
 * is this module's actual scope.
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

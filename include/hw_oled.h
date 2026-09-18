#ifndef HW_OLED_H
#define HW_OLED_H

/* hw_oled - native C driver for the FNK0100 case's SSD1306-compatible 128x64 monochrome OLED (I2C 0x3C, bus 1). Confirmed working on real hardware, 2026-08-21 - see TESTING.md. SECONDARY display only - the 4.3" DSI touchscreen (see ui.h) is primary; keep content here brief/glanceable. Text-only API by design. */

#define HW_OLED_WIDTH   128
#define HW_OLED_HEIGHT  64
#define HW_OLED_LINES   8   /* 64px / 8px per text line (7px font + 1px gap) */
#define HW_OLED_COLS    21  /* 128px / 6px per char (5px font + 1px gap) */

/* hw_oled_open - open /dev/i2c-1, address the display, run the SSD1306 init sequence, and blank the screen. Returns an fd, or -1 on failure (treat as non-fatal). */

/* hw_oled_clear - clear the in-memory framebuffer only; call hw_oled_display() afterward to flush to screen. fd < 0 is a no-op. */

/* hw_oled_draw_text - draw one line of text (up to HW_OLED_COLS chars, truncated not wrapped), clearing the rest of that line first. Call hw_oled_display() to flush. No-op on fd < 0, out-of-range line, or NULL text. */

/* hw_oled_display - push the entire in-memory framebuffer to the physical display over I2C. fd < 0 is a no-op. */

/* hw_oled_close - release the I2C file descriptor. Safe with fd < 0. */

#ifdef __linux__

int hw_oled_open(void);
void hw_oled_clear(int fd);
void hw_oled_draw_text(int fd, int line, const char *text);
void hw_oled_display(int fd);
void hw_oled_close(int fd);

#else

/* Non-Linux build: harmless no-op stubs, one platform branch here instead of scattered #ifdefs at every call site (see hw_expansion.h). */
static inline int hw_oled_open(void) { return -1; }
static inline void hw_oled_clear(int fd) { (void)fd; }
static inline void hw_oled_draw_text(int fd, int line, const char *text)
    { (void)fd; (void)line; (void)text; }
static inline void hw_oled_display(int fd) { (void)fd; }
static inline void hw_oled_close(int fd) { (void)fd; }

#endif /* __linux__ */

#endif /* HW_OLED_H */

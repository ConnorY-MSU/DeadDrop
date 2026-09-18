/* hw_oled.c - Linux-only, written against real sourced references. See include/hw_oled.h for full status note. */

#ifdef __linux__

#include "hw_oled.h"
#include "hw_oled_font.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OLED_I2C_BUS      "/dev/i2c-1"
#define OLED_I2C_ADDRESS  0x3C  /* confirmed via Freenove's api_oled.py */

#define OLED_CONTROL_COMMAND 0x00 /* Co=0, D/C#=0: stream of command bytes */
#define OLED_CONTROL_DATA    0x40 /* Co=0, D/C#=1: stream of data bytes */

/* Framebuffer: 8 pages x 128 columns, one byte per column per page (LSB = top pixel) - the SSD1306's native GDDRAM layout. One static buffer (one physical display). */
static uint8_t framebuffer[HW_OLED_HEIGHT / 8][HW_OLED_WIDTH];

/* SSD1306 128x64 init sequence, internal charge pump (SSD1306_SWITCHCAPVCC). Traced byte-for-byte against Adafruit_SSD1306.cpp's begin(). Sent as one I2C command-stream write. */
static const uint8_t oled_init_sequence[] = {
    0xAE,             /* DISPLAYOFF */
    0xD5, 0x80,       /* SETDISPLAYCLOCKDIV, suggested ratio */
    0xA8, 0x3F,       /* SETMULTIPLEX, height-1 = 63 for a 64px-tall panel */
    0xD3, 0x00,       /* SETDISPLAYOFFSET, none */
    0x40,             /* SETSTARTLINE | 0 */
    0x8D, 0x14,       /* CHARGEPUMP, internal VCC (0x14, not 0x10) */
    0x20, 0x00,       /* MEMORYMODE, horizontal addressing */
    0xA1,             /* SEGREMAP | 0x1 */
    0xC8,             /* COMSCANDEC */
    0xDA, 0x12,       /* SETCOMPINS, 0x12 for a 128x64 panel */
    0x81, 0xCF,       /* SETCONTRAST, 0xCF for 128x64 + internal VCC */
    0xD9, 0xF1,       /* SETPRECHARGE, 0xF1 for internal VCC */
    0xDB, 0x40,       /* SETVCOMDETECT */
    0xA4,             /* DISPLAYALLON_RESUME (show RAM contents, not all-on) */
    0xA6,             /* NORMALDISPLAY (not inverted) */
    0x2E,             /* DEACTIVATE_SCROLL */
    0xAF              /* DISPLAYON */
};

/* Largest single write this file issues is one framebuffer chunk (32 bytes, see hw_oled_display()); comfortably under this fixed stack buffer, so malloc() is never needed. */
#define I2C_WRITE_BUF_MAX 40

static int i2c_write(int fd, uint8_t control_byte,
                      const uint8_t *data, size_t len)
{
    uint8_t buf[I2C_WRITE_BUF_MAX];

    if (len + 1 > sizeof(buf)) {
        return -1;
    }
    buf[0] = control_byte;
    memcpy(buf + 1, data, len);

    return (write(fd, buf, len + 1) == (ssize_t)(len + 1)) ? 0 : -1;
}

static int i2c_write_commands(int fd, const uint8_t *cmds, size_t len)
{
    return i2c_write(fd, OLED_CONTROL_COMMAND, cmds, len);
}

int hw_oled_open(void)
{
    int fd = open(OLED_I2C_BUS, O_RDWR);
    if (fd < 0) {
        fprintf(stderr,
            "hw_oled_open: cannot open %s (case hardware absent or I2C "
            "not enabled? continuing without it)\n", OLED_I2C_BUS);
        return -1;
    }

    if (ioctl(fd, I2C_SLAVE, OLED_I2C_ADDRESS) < 0) {
        fprintf(stderr,
            "hw_oled_open: ioctl(I2C_SLAVE, 0x%02x) failed - continuing "
            "without the OLED\n", OLED_I2C_ADDRESS);
        close(fd);
        return -1;
    }

    if (i2c_write_commands(fd, oled_init_sequence,
                            sizeof(oled_init_sequence)) != 0) {
        fprintf(stderr, "hw_oled_open: init sequence write failed\n");
        close(fd);
        return -1;
    }

    memset(framebuffer, 0, sizeof(framebuffer));
    hw_oled_display(fd);

    return fd;
}

void hw_oled_clear(int fd)
{
    if (fd < 0) {
        return;
    }
    memset(framebuffer, 0, sizeof(framebuffer));
}

void hw_oled_draw_text(int fd, int line, const char *text)
{
    int col;
    size_t i;

    if (fd < 0 || text == NULL || line < 0 || line >= HW_OLED_LINES) {
        return;
    }

    /* Clear the whole line first, so a shorter string correctly overwrites whatever a longer one previously left there. */
    memset(framebuffer[line], 0, HW_OLED_WIDTH);

    for (i = 0, col = 0; text[i] != '\0' && col + 5 <= HW_OLED_WIDTH; i++) {
        /* hw_oled_font is indexed by raw byte value, 5 bytes/char, full 0-255 range - see hw_oled_font.h. Non-printable bytes index safely, just look wrong. */
        unsigned char c = (unsigned char)text[i];
        const unsigned char *glyph = &hw_oled_font[(size_t)c * 5];
        int k;

        for (k = 0; k < 5; k++) {
            framebuffer[line][col + k] = glyph[k];
        }
        col += 6; /* 5px glyph + 1px gap */
    }
}

void hw_oled_display(int fd)
{
    int page;
    static const uint8_t set_addr_range[] = {
        0x21, 0x00, HW_OLED_WIDTH - 1,             /* COLUMNADDR: 0..127 */
        0x22, 0x00, (HW_OLED_HEIGHT / 8) - 1        /* PAGEADDR: 0..7 */
    };

    if (fd < 0) {
        return;
    }

    if (i2c_write_commands(fd, set_addr_range, sizeof(set_addr_range)) != 0) {
        return;
    }

    /* Stream the framebuffer in modest chunks rather than one 1024-byte write, to stay under I2C transaction-size limits that vary by hardware. */
    for (page = 0; page < HW_OLED_HEIGHT / 8; page++) {
        int offset;
        for (offset = 0; offset < HW_OLED_WIDTH; offset += 32) {
            int chunk = (HW_OLED_WIDTH - offset < 32)
                        ? (HW_OLED_WIDTH - offset) : 32;
            if (i2c_write(fd, OLED_CONTROL_DATA,
                           &framebuffer[page][offset], (size_t)chunk) != 0) {
                return;
            }
        }
    }
}

void hw_oled_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

#endif /* __linux__ */

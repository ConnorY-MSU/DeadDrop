/* hw_expansion.c - Linux-only (see #ifdef guard below); compiles to nothing on non-Linux so Windows dev builds keep working. See COMMENT_ARCHIVE.md. */

#ifdef __linux__

#include "hw_expansion.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <stdio.h>
#include <string.h>

/* Confirmed against Freenove's own api_expansion.py (IIC_ADDRESS and REG_* constants), not guessed. */
#define FNK0100_I2C_BUS      "/dev/i2c-1"
#define FNK0100_I2C_ADDRESS  0x21

#define REG_LED_SPECIFIED    0x01  /* [led_id, r, g, b] - one LED */
#define REG_LED_ALL          0x02  /* [r, g, b] - every LED at once */
#define REG_LED_MODE         0x03  /* single byte, see hw_led_mode */

/* Writes reg+data as one raw I2C write() (not I2C_SMBUS ioctl), matching Freenove's "I2C Block Write" format. Returns 0/-1. See COMMENT_ARCHIVE.md. */
static int i2c_write_block(int fd, uint8_t reg, const uint8_t *data, size_t len)
{
    uint8_t buf[8]; /* room for the largest current write (5 bytes) plus headroom for future registers */

    if (len + 1 > sizeof(buf)) {
        return -1;
    }
    buf[0] = reg;
    memcpy(buf + 1, data, len);

    if (write(fd, buf, len + 1) != (ssize_t)(len + 1)) {
        return -1;
    }
    return 0;
}

static int i2c_write_byte(int fd, uint8_t reg, uint8_t value)
{
    return i2c_write_block(fd, reg, &value, 1);
}

int hw_expansion_open(void)
{
    int fd = open(FNK0100_I2C_BUS, O_RDWR);
    if (fd < 0) {
        fprintf(stderr,
            "hw_expansion_open: cannot open %s (case hardware absent or "
            "I2C not enabled? continuing without it)\n", FNK0100_I2C_BUS);
        return -1;
    }

    if (ioctl(fd, I2C_SLAVE, FNK0100_I2C_ADDRESS) < 0) {
        fprintf(stderr,
            "hw_expansion_open: ioctl(I2C_SLAVE, 0x%02x) failed - "
            "continuing without case hardware\n", FNK0100_I2C_ADDRESS);
        close(fd);
        return -1;
    }

    return fd;
}

void hw_expansion_set_led_mode(int fd, hw_led_mode mode)
{
    if (fd < 0) {
        return;
    }
    i2c_write_byte(fd, REG_LED_MODE, (uint8_t)mode);
}

void hw_expansion_set_status_color(int fd, hw_connection_status status)
{
    uint8_t rgb[3];

    if (fd < 0) {
        return;
    }

    switch (status) {
        case HW_STATUS_DISCONNECTED:
            rgb[0] = 255; rgb[1] = 0;   rgb[2] = 0;   /* red */
            break;
        case HW_STATUS_CONNECTING:
            rgb[0] = 255; rgb[1] = 191; rgb[2] = 0;   /* amber */
            break;
        case HW_STATUS_CONNECTED:
            rgb[0] = 0;   rgb[1] = 200; rgb[2] = 0;   /* green */
            break;
        case HW_STATUS_MSG_CONNECTED:
            rgb[0] = 0;   rgb[1] = 100; rgb[2] = 255; /* blue */
            break;
        case HW_STATUS_MSG_DISCONNECTED:
            rgb[0] = 255; rgb[1] = 100; rgb[2] = 0;   /* orange */
            break;
        default:
            return; /* unrecognized status - do nothing rather than write something arbitrary to a physical light */
    }

    i2c_write_block(fd, REG_LED_ALL, rgb, sizeof(rgb));
}

void hw_expansion_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

#endif /* __linux__ */

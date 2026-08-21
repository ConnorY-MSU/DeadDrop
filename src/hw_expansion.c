/*
 * hw_expansion.c - see include/hw_expansion.h for the full status note:
 * this is Linux-only, written against Freenove's own published register
 * protocol for the FNK0100 case's expansion board, but NOT yet compiled
 * or run against real hardware (no Pi OS installed yet as of writing).
 *
 * Only ever built on Linux - see the #ifdef __linux__ guard below and
 * the matching build-line note in this file's header comment. Windows
 * dev-machine builds of client.c/server.c must keep working unmodified
 * until this has real hardware to run against; this file compiling to
 * nothing (rather than failing to compile) on a non-Linux target is
 * deliberate, not an oversight.
 */

#ifdef __linux__

#include "hw_expansion.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <stdio.h>
#include <string.h>

/* Confirmed against Freenove's own api_expansion.py (Expansion.IIC_ADDRESS
 * and the FNK0100 class's REG_* constants) - not guessed, not derived
 * from the product description alone. */
#define FNK0100_I2C_BUS      "/dev/i2c-1"
#define FNK0100_I2C_ADDRESS  0x21

#define REG_LED_SPECIFIED    0x01  /* [led_id, r, g, b] - one LED */
#define REG_LED_ALL          0x02  /* [r, g, b] - every LED at once */
#define REG_LED_MODE         0x03  /* single byte, see hw_led_mode */

/* Writes reg followed by the bytes in data as one raw I2C write
 * transaction. This deliberately goes through the plain character-
 * device write() path (after ioctl(I2C_SLAVE) in hw_expansion_open()),
 * NOT the I2C_SMBUS ioctl - confirmed this is the right choice, not
 * assumed: Freenove's own reference code uses Python smbus's
 * write_i2c_block_data(), which the Linux kernel's own SMBus protocol
 * documentation (docs.kernel.org/i2c/smbus-protocol.html) specifies as
 * "I2C Block Write" - wire format "Comm [A] Data [A] Data [A] ...",
 * explicitly WITHOUT the count byte the *standard* SMBus "Block Write"
 * protocol inserts between the register and the data. A plain write()
 * of [reg, data...] on the character device produces exactly that same
 * byte sequence. Verified against the kernel's own protocol spec, not
 * hardware - see this file's header comment for what "verified" does
 * and doesn't mean here until real hardware exists.
 *
 * Returns 0 on success, -1 on failure. Deliberately does not log on
 * every transient I2C failure - see the callers' own "fd < 0 is a
 * no-op" contract; a single dropped LED-color write is not worth
 * spamming stderr over on a device whose whole purpose is a nice-to-
 * have status indicator, not core protocol functionality.
 */
static int i2c_write_block(int fd, uint8_t reg, const uint8_t *data, size_t len)
{
    uint8_t buf[8]; /* largest current write is REG_LED_SPECIFIED's 4 bytes
                      * (led_id,r,g,b) + 1 register byte = 5; sized with
                      * headroom rather than exactly, so a future register
                      * needing a couple more bytes doesn't silently
                      * truncate here. */

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
        default:
            return; /* unrecognized status - do nothing rather than
                      * write something arbitrary to a physical light */
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

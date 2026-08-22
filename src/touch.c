#include <stdio.h>
#include <string.h>

#include "touch.h"

#ifdef __linux__

#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#define TOUCH_DEV_GLOB_MAX 32

/* Per-fd state needed to normalize raw ABS_X/ABS_Y readings - queried
 * once at open time via EVIOCGABS and cached here, keyed by fd. A
 * small fixed table rather than a dynamic structure returned to the
 * caller: this project only ever opens one touch device at a time. */
#define TOUCH_MAX_OPEN_FDS 4
static struct {
    int fd;
    int x_min, x_max;
    int y_min, y_max;
} g_touch_state[TOUCH_MAX_OPEN_FDS];
static int g_touch_state_count = 0;

static int bit_is_set(const unsigned char *bits, int bit)
{
    return (bits[bit / 8] >> (bit % 8)) & 1;
}

/*
 * device_is_touchscreen - true if this fd's device reports ABS_X,
 * ABS_Y, and INPUT_PROP_DIRECT - the capability signature confirmed
 * against the real ft5x06 touch controller (see touch.h), not
 * assumed. A mouse or trackpad has ABS/REL axes without
 * INPUT_PROP_DIRECT; a keyboard has neither.
 */
static int device_is_touchscreen(int fd)
{
    unsigned char abs_bits[(ABS_MAX + 7) / 8];
    unsigned char prop_bits[(INPUT_PROP_MAX + 7) / 8];

    memset(abs_bits, 0, sizeof(abs_bits));
    memset(prop_bits, 0, sizeof(prop_bits));

    if (ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(abs_bits)), abs_bits) < 0) {
        return 0;
    }
    if (!bit_is_set(abs_bits, ABS_X) || !bit_is_set(abs_bits, ABS_Y)) {
        return 0;
    }

    if (ioctl(fd, EVIOCGPROP(sizeof(prop_bits)), prop_bits) < 0) {
        return 0;
    }
    if (!bit_is_set(prop_bits, INPUT_PROP_DIRECT)) {
        return 0;
    }

    return 1;
}

int touch_open(void)
{
    int i;

    if (g_touch_state_count >= TOUCH_MAX_OPEN_FDS) {
        return -1;
    }

    for (i = 0; i < TOUCH_DEV_GLOB_MAX; i++) {
        char path[32];
        int fd;
        struct input_absinfo x_info, y_info;

        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            continue;
        }

        if (!device_is_touchscreen(fd)) {
            close(fd);
            continue;
        }

        if (ioctl(fd, EVIOCGABS(ABS_X), &x_info) < 0 ||
            ioctl(fd, EVIOCGABS(ABS_Y), &y_info) < 0) {
            close(fd);
            continue;
        }

        g_touch_state[g_touch_state_count].fd = fd;
        g_touch_state[g_touch_state_count].x_min = x_info.minimum;
        g_touch_state[g_touch_state_count].x_max = x_info.maximum;
        g_touch_state[g_touch_state_count].y_min = y_info.minimum;
        g_touch_state[g_touch_state_count].y_max = y_info.maximum;
        g_touch_state_count++;

        return fd;
    }

    return -1;
}

static int find_state(int fd)
{
    int i;
    for (i = 0; i < g_touch_state_count; i++) {
        if (g_touch_state[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

int touch_read_tap(int fd, touch_point *out_point, int timeout_ms)
{
    int state_idx = find_state(fd);
    struct pollfd pfd;
    int last_x = 0, last_y = 0;
    int have_xy = 0;

    if (fd < 0 || state_idx < 0 || out_point == NULL) {
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;

    for (;;) {
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0) {
            return -1;
        }
        if (pr == 0) {
            return 0; /* timeout, nothing pending */
        }

        for (;;) {
            struct input_event ev;
            ssize_t n = read(fd, &ev, sizeof(ev));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break; /* drained everything currently pending */
                }
                return -1; /* a real error - e.g. device unplugged */
            }
            if (n != (ssize_t)sizeof(ev)) {
                return -1; /* short read - device in a bad state */
            }

            if (ev.type == EV_ABS && ev.code == ABS_X) {
                last_x = ev.value;
                have_xy |= 1;
            } else if (ev.type == EV_ABS && ev.code == ABS_Y) {
                last_y = ev.value;
                have_xy |= 2;
            } else if (ev.type == EV_KEY && ev.code == BTN_TOUCH &&
                       ev.value == 1 && have_xy == 3) {
                /* Touch-down, and we have a real X/Y pair for it -
                 * per the "type A" evdev convention, ABS_X/ABS_Y are
                 * reported before BTN_TOUCH within the same event
                 * packet, so both are already current by the time
                 * this fires. */
                int x_range = g_touch_state[state_idx].x_max -
                              g_touch_state[state_idx].x_min;
                int y_range = g_touch_state[state_idx].y_max -
                              g_touch_state[state_idx].y_min;

                out_point->x = (x_range > 0)
                    ? (float)(last_x - g_touch_state[state_idx].x_min) /
                          (float)x_range
                    : 0.0f;
                out_point->y = (y_range > 0)
                    ? (float)(last_y - g_touch_state[state_idx].y_min) /
                          (float)y_range
                    : 0.0f;
                return 1;
            }
        }
        /* Drained this batch with no completed tap yet (e.g. touch-up,
         * or a mid-drag position update) - poll again for the rest of
         * the caller's timeout rather than returning a false timeout. */
    }
}

void touch_close(int fd)
{
    int state_idx = find_state(fd);

    if (fd >= 0) {
        close(fd);
    }
    if (state_idx >= 0) {
        g_touch_state[state_idx] = g_touch_state[g_touch_state_count - 1];
        g_touch_state_count--;
    }
}

#else /* !__linux__ */

/* No touchscreen exists on this project's Windows dev machine - these
 * stubs exist only so callers can link on either platform without
 * #ifdef guards at every call site, matching hw_expansion.h's
 * established precedent. */

int touch_open(void)
{
    return -1;
}

int touch_read_tap(int fd, touch_point *out_point, int timeout_ms)
{
    (void)fd;
    (void)out_point;
    (void)timeout_ms;
    return -1;
}

void touch_close(int fd)
{
    (void)fd;
}

#endif /* __linux__ */

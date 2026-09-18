#include "hw_volume.h"
#include "hw_tts.h"

#ifdef __linux__

/* Thin pass-through to hw_tts_set/get_volume() (software gain relay; the old ALSA `amixer` control had no real effect). See COMMENT_ARCHIVE.md. */

int hw_volume_set(int percent)
{
    hw_tts_set_volume(percent);
    return 0;
}

int hw_volume_get(void)
{
    return hw_tts_get_volume();
}

#endif /* __linux__ */

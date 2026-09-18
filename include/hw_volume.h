#ifndef HW_VOLUME_H
#define HW_VOLUME_H

/* hw_volume - speaker volume control; thin pass-through to hw_tts_set/get_volume() (software gain relay, not ALSA). See COMMENT_ARCHIVE.md. */

#ifdef __linux__

/* hw_volume_set - set output volume to `percent` (clamped to [0, 100]); always returns 0. */
int hw_volume_set(int percent);

/* hw_volume_get - read the current output volume as a percentage (0-100). */
int hw_volume_get(void);

#else

static inline int hw_volume_set(int percent) { (void)percent; return -1; }
static inline int hw_volume_get(void) { return -1; }

#endif /* __linux__ */

#endif /* HW_VOLUME_H */

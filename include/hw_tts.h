#ifndef HW_TTS_H
#define HW_TTS_H

/* hw_tts - optional text-to-speech via a RESIDENT Piper process piped to system audio; persistent process+queue design (2026-08-25) avoids per-message model-load latency. Piper (GPL-3.0) invoked as a subprocess only. Gated behind #ifdef __linux__. See COMMENT_ARCHIVE.md. */

/* Path to the Piper voice model (.onnx); a matching <path>.json config must sit alongside it. Currently MEDIUM quality; see COMMENT_ARCHIVE.md. */
#define HW_TTS_MODEL_PATH "/home/connor/piper-voices/current.onnx"

/* Absolute path to the piper executable - NOT looked up via PATH, since piper lives in a venv whose bin/ isn't on the hardened systemd service's PATH. */
#define HW_TTS_PIPER_PATH "/home/connor/piper-venv/bin/piper"

/* Output sample rate - must match the voice model's own native rate (its .json "sample_rate" field); a mismatch plays back at the wrong speed/pitch, no error. */
#define HW_TTS_SAMPLE_RATE_HZ 22050

/* hw_tts_init - start the resident Piper + aplay pipeline and background speaker thread. Call once at startup alongside hw_expansion_open()/hw_oled_open(). Returns 0/-1 (always non-fatal to the caller). */
#ifdef __linux__
int hw_tts_init(void);
#else
static inline int hw_tts_init(void) { return -1; }
#endif

/* hw_tts_speak - enqueue text to be spoken, in order, by the resident Piper process; returns immediately, never blocks, silently drops if the queue is full (best-effort, unlike outbox.c's queue). text must be a real NUL-terminated C string (msg.body is not - callers must copy it first). */
#ifdef __linux__
void hw_tts_speak(const char *text);
#else
static inline void hw_tts_speak(const char *text) { (void)text; }
#endif

/* hw_tts_stop_and_clear - immediately cut off whatever is playing and drop everything queued. Only session_perform_local_destroy() should call this. SIGKILL + respawn on the speaker thread; stays fast, never blocks. */
#ifdef __linux__
void hw_tts_stop_and_clear(void);
#else
static inline void hw_tts_stop_and_clear(void) { }
#endif

/* hw_tts_shutdown - stop the speaker thread and kill the resident piper/aplay processes. Call once at the end of main(), alongside hw_expansion_close()/hw_oled_close(). */
#ifdef __linux__
void hw_tts_shutdown(void);
#else
static inline void hw_tts_shutdown(void) { }
#endif

/* hw_tts_set_volume / hw_tts_get_volume - real, software-applied output gain, added 2026-08-27 since this hardware's HDMI path has no real ALSA-mixer volume control. A relay thread (hw_tts.c) multiplies every sample by this gain. percent is clamped to [0, 100]. */
#ifdef __linux__
void hw_tts_set_volume(int percent);
int hw_tts_get_volume(void);
#else
static inline void hw_tts_set_volume(int percent) { (void)percent; }
static inline int hw_tts_get_volume(void) { return -1; }
#endif

#endif /* HW_TTS_H */

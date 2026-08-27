#ifndef HW_TTS_H
#define HW_TTS_H

/*
 * hw_tts - optional text-to-speech for incoming messages, via a
 * RESIDENT Piper (neural TTS) process piped to the system's default
 * audio output. Week 4 physical-build addition; replaced the original
 * espeak-ng implementation 2026-08-25, then redesigned the same day
 * from "fork a fresh piper+aplay per message" to a persistent
 * process + queue, specifically to avoid per-message model-load
 * latency - see hw_tts_init()'s comment for the full reasoning.
 *
 * Unlike hw_expansion/hw_oled, this needs no custom protocol at all -
 * the FNK0100's speakers are standard analog/optical audio out through
 * the Pi's own audio path (confirmed in Freenove's own component
 * chapter - "audio separation/amplification circuit", no I2C or other
 * special interface for the speakers themselves).
 *
 * Piper is GPL-3.0 licensed (as of the OHF-Voice/piper1-gpl fork this
 * project uses - the original rhasspy/piper was MIT but went read-only
 * in Oct 2025). This module invokes it as a separate subprocess via
 * fork()/exec(), communicating only through pipes - the same "mere
 * aggregation" pattern already used for espeak-ng (also GPL), which
 * does not extend GPL to this project's own codebase. Worth stating
 * plainly rather than leaving implicit, same as every other dependency
 * this project has been precise about.
 *
 * Currently running a MEDIUM-quality voice model (see HW_TTS_MODEL_PATH)
 * - a low-quality tier would load faster (matters at startup and at
 * every destroy-triggered restart, see hw_tts_stop_and_clear()) and run
 * cheaper per utterance, but medium was chosen instead for better
 * output quality; drop to low if real-hardware testing shows the
 * load/synthesis cost is actually a problem in practice, not
 * preemptively. A custom-trained voice is planned to replace this one
 * later - swap the files at HW_TTS_MODEL_PATH, no code change needed.
 *
 * Voice model files (.onnx + matching .onnx.json) are intentionally
 * gitignored - large third-party binary assets, device-local only,
 * never committed. See this project's .gitignore.
 *
 * Gated behind #ifdef __linux__ like the other hw_* modules, for the
 * same reason as before: TTS is a Pi-only feature here, not because
 * fork()/exec()/pthread has no Windows equivalent at all.
 */

/* Path to the Piper voice model (.onnx). A matching <path>.json config
 * file must sit alongside it (Piper requires both, same filename
 * prefix) - not referenced directly here since Piper finds it itself
 * from the .onnx path. Swapping in the planned custom voice later is
 * just replacing both files at this path - no code change needed,
 * which is the entire point of keeping this a single named constant
 * instead of hardcoding a filename inline in hw_tts.c. Pick a
 * low-quality tier deliberately (see this header's top comment). */
#define HW_TTS_MODEL_PATH "/home/connor/piper-voices/current.onnx"

/* Absolute path to the piper executable - deliberately NOT looked up
 * via PATH (execlp) the way aplay is, because piper is installed into a
 * Python venv (verified 2026-08-25 on bravo: pip install piper-tts into
 * ~/piper-venv, since the actively-maintained OHF-Voice/piper1-gpl fork
 * didn't have a confirmed standalone-binary release path - see GPS
 * Location Sharing.md's sibling research for the same investigation).
 * A venv's bin/ directory is not on the default PATH, and definitely
 * should not be assumed to be on whatever restricted PATH the hardened
 * systemd service sees - hardcoding the absolute path here sidesteps
 * that whole class of environment-dependent failure entirely. Update
 * this if the venv ever moves. */
#define HW_TTS_PIPER_PATH "/home/connor/piper-venv/bin/piper"

/* Output sample rate, must match the voice model's own native rate -
 * check the model's .json config file's "sample_rate" field, do NOT
 * assume this default is correct for every voice. A mismatch here
 * doesn't error - it just plays back at the wrong speed/pitch, a sneaky
 * bug class worth checking explicitly, especially when the planned
 * custom voice is dropped in later (it may not share this rate). Most
 * default English Piper voices use 22050; verify, don't assume. */
#define HW_TTS_SAMPLE_RATE_HZ 22050

/*
 * hw_tts_init - start the resident Piper + aplay pipeline and the
 * background speaker thread that owns it. Call once at program
 * startup, alongside hw_expansion_open()/hw_oled_open() (see
 * client.c/server.c's main() - same "physical resource, own lifecycle,
 * opened once and kept for the process's whole life" pattern already
 * established there).
 *
 * WHY RESIDENT, NOT PER-MESSAGE: Piper's ONNX model load has real
 * startup cost, unlike espeak-ng's near-instant formant synthesis.
 * Forking a fresh piper process per message (the original design of
 * this rewrite, before this revision) would mean paying that load cost
 * on every single spoken message - explicitly requested to be avoided.
 * Keeping one piper process alive for the program's whole lifetime,
 * fed one line of text per message via a persistent stdin pipe, pays
 * that cost exactly once.
 *
 * Messages are QUEUED (see hw_tts_speak()) and spoken strictly in the
 * order received - a burst of incoming messages never overlaps or
 * garbles audio, they simply play back-to-back. Nothing interrupts an
 * in-progress or queued utterance except an explicit
 * hw_tts_stop_and_clear() call (see below) - notably, this means
 * neither a new incoming message nor anything else routine cuts off
 * what's currently playing. Only "/destroy" does, via
 * session_perform_local_destroy() calling hw_tts_stop_and_clear()
 * directly.
 *
 * Returns 0 on success, -1 on any failure (piper/aplay not installed,
 * pipe()/fork()/pthread_create() failure, etc). Always non-fatal to the
 * caller - same principle as every other hw_* module's hardware-absence
 * handling: this project's core protocol functionality must never
 * depend on this being present or working. On -1, hw_tts_speak() calls
 * that follow are safe no-ops (nothing to enqueue into).
 */
#ifdef __linux__
int hw_tts_init(void);
#else
static inline int hw_tts_init(void) { return -1; }
#endif

/*
 * hw_tts_speak - enqueue text to be spoken, in order, by the resident
 * Piper process. Returns immediately - never blocks on synthesis or
 * playback, so this never delays message handling. If the queue is
 * already full (HW_TTS_QUEUE_MAX pending utterances - a burst far
 * beyond normal chat pace), the new text is silently dropped: TTS is
 * inherently best-effort supplementary output, not something a message
 * being delivered/displayed depends on, unlike outbox.c's queue (a
 * dropped outbound chat message matters; a dropped spoken notification
 * for a message that's already visible in the chat log does not).
 *
 * text: a real NUL-terminated C string. A parsed message body
 *       (dd_parsed_message.body) is NOT NUL-terminated on its own -
 *       length-prefixed per PROTOCOL.md, not a C string - so callers
 *       must copy it into a real NUL-terminated buffer first; passing
 *       msg.body directly here is a bug, not something this function
 *       can detect or protect against.
 *
 * Truncates text longer than a sane spoken length rather than reading
 * an entire message aloud in full. Silently does nothing if
 * hw_tts_init() was never called or failed, or if text is NULL.
 */
#ifdef __linux__
void hw_tts_speak(const char *text);
#else
static inline void hw_tts_speak(const char *text) { (void)text; }
#endif

/*
 * hw_tts_stop_and_clear - immediately cut off whatever is currently
 * playing AND drop every queued-but-not-yet-spoken message. The ONLY
 * thing that should call this is session_perform_local_destroy() - see
 * its own comment in session.c for why that one function is the single
 * shared hook for all three "/destroy" call sites (local command, the
 * received DD_MSG_DESTROY case, and ui.c's offline handling). Nothing
 * else in this project should call this - a routine event (a new
 * message arriving, a disconnect, a reconnect) must never silence
 * TTS mid-utterance, only an actual destroy does.
 *
 * Implementation note: "immediately cut off" for already-buffered audio
 * genuinely requires killing and restarting the underlying piper/aplay
 * processes (there's no way to "unplay" audio bytes already handed to
 * aplay/ALSA) - this is not a graceful stop, it's SIGKILL + respawn.
 * The restart happens on the background speaker thread, not
 * synchronously in this call, so calling this is fast and never blocks
 * the destroy path itself.
 *
 * Safe to call even if hw_tts_init() was never called or failed - a
 * no-op in that case, same non-fatal-absence principle as everywhere
 * else in this module.
 */
#ifdef __linux__
void hw_tts_stop_and_clear(void);
#else
static inline void hw_tts_stop_and_clear(void) { }
#endif

/*
 * hw_tts_shutdown - stop the speaker thread and kill the resident
 * piper/aplay processes. Call once at the very end of main(), alongside
 * hw_expansion_close()/hw_oled_close() (see client.c/server.c). Safe to
 * call even if hw_tts_init() was never called or failed.
 */
#ifdef __linux__
void hw_tts_shutdown(void);
#else
static inline void hw_tts_shutdown(void) { }
#endif

#endif /* HW_TTS_H */

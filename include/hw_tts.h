#ifndef HW_TTS_H
#define HW_TTS_H

/*
 * hw_tts - optional text-to-speech for incoming messages, via espeak-ng
 * piped to the system's default audio output. Week 4 physical-build
 * addition.
 *
 * Unlike hw_expansion/hw_oled, this needs no custom protocol at all -
 * the FNK0100's speakers are standard analog/optical audio out through
 * the Pi's own audio path (confirmed in Freenove's own component
 * chapter - "audio separation/amplification circuit", no I2C or other
 * special interface for the speakers themselves), so this is "run a
 * command", not a hardware register protocol. Recommend installing
 * espeak-ng specifically: lightweight, fully offline (no API keys, no
 * network dependency this project shouldn't need for something this
 * simple), and available directly via apt on Raspberry Pi OS.
 *
 * Gated behind #ifdef __linux__ like the other hw_* modules, though for
 * a different reason than hw_expansion/hw_oled: this project has no
 * need for a Windows TTS path (TTS is a Pi-only feature here), not
 * because fork()/exec() has no Windows equivalent at all.
 */

/*
 * hw_tts_speak - speak the given text aloud, if espeak-ng is installed
 * and reachable via PATH. Fire-and-forget: spawns the process and
 * returns immediately without blocking on speech synthesis finishing,
 * so this never delays message handling - callers must not depend on
 * the speech having started, let alone finished, by the time this
 * returns. Uses the standard double-fork technique internally so the
 * actual espeak-ng process gets reparented to init and reaped
 * automatically on exit, rather than left as a zombie under this
 * project's long-running server/client process - a naive single
 * fork()+exec() with no wait() at all would leak a zombie process
 * table entry per message spoken, a real (if slow) resource leak over
 * a long-running session.
 *
 * text: a real NUL-terminated C string. A parsed message body
 *       (sl_parsed_message.body) is NOT NUL-terminated on its own -
 *       length-prefixed per PROTOCOL.md, not a C string - so callers
 *       must copy it into a real NUL-terminated buffer first; passing
 *       msg.body directly here is a bug, not something this function
 *       can detect or protect against.
 *
 * Truncates text longer than a sane spoken length rather than reading
 * an entire message aloud in full. Silently does nothing if espeak-ng
 * isn't installed, if fork() fails, or if text is NULL - this
 * project's core protocol functionality must never depend on this
 * being present or working, same principle as hw_expansion/hw_oled's
 * hardware-absence handling.
 */

#ifdef __linux__
void hw_tts_speak(const char *text);
#else
static inline void hw_tts_speak(const char *text) { (void)text; }
#endif

#endif /* HW_TTS_H */

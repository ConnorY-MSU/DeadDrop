/*
 * hw_tts.c - see include/hw_tts.h for the full contract. Linux-only,
 * same "reviewed, not yet run against real hardware" status as
 * hw_expansion.c/hw_oled.c, though the risk profile here is much lower:
 * this is standard POSIX fork()/exec()/waitpid(), not a hand-derived
 * hardware protocol - the part most worth real verification once
 * hardware exists is simply "is espeak-ng actually installed and does
 * it produce audible output through this specific case's speakers",
 * not "did this code correctly implement some external spec".
 */

#ifdef __linux__

#include "hw_tts.h"

#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

/* A sane spoken-aloud length cap - this project's messages can be up to
 * SL_MAX_BODY_LEN (64KB) per PROTOCOL.md, and nobody wants that read
 * aloud in full. Deliberately not tied to SL_MAX_BODY_LEN (message.h
 * isn't even included here) - this is a UX choice about what's
 * reasonable to speak, unrelated to the protocol's own length limit. */
#define HW_TTS_MAX_CHARS 200

void hw_tts_speak(const char *text)
{
    pid_t pid;
    char truncated[HW_TTS_MAX_CHARS + 1];
    size_t len;

    if (text == NULL) {
        return;
    }

    len = strlen(text);
    if (len > HW_TTS_MAX_CHARS) {
        len = HW_TTS_MAX_CHARS;
    }
    memcpy(truncated, text, len);
    truncated[len] = '\0';

    pid = fork();
    if (pid < 0) {
        return; /* fork failed - not fatal, just skip speaking this one */
    }

    if (pid == 0) {
        /* First (intermediate) child. */
        pid_t grandchild = fork();

        if (grandchild < 0) {
            _exit(1);
        }
        if (grandchild == 0) {
            /* Grandchild: the process that actually becomes espeak-ng.
             * If espeak-ng isn't on PATH, execlp() itself fails and this
             * process just exits - nothing upstream blocks or needs to
             * notice either way, matching hw_tts_speak()'s "absence is
             * non-fatal" contract. */
            execlp("espeak-ng", "espeak-ng", truncated, (char *)NULL);
            _exit(127); /* only reached if execlp() failed */
        }

        /* Intermediate child exits immediately WITHOUT waiting for the
         * grandchild - this is what makes the grandchild an orphan,
         * reparented to init (PID 1), which reaps it automatically when
         * it exits. That's what avoids a zombie process accumulating
         * under THIS project's long-running server/client process for
         * every message spoken. */
        _exit(0);
    }

    /* Parent: reap the intermediate child. This waitpid() returns
     * almost immediately (microseconds) since the intermediate child
     * exits right after its own fork() call above - it is NOT waiting
     * for the grandchild/espeak-ng process to finish speaking, which is
     * the entire point of the double-fork: this call blocks for as long
     * as it takes the intermediate child to exit, not as long as it
     * takes to speak the message. */
    waitpid(pid, NULL, 0);
}

#endif /* __linux__ */

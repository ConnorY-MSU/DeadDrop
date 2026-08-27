/* Standalone diagnostic - NOT part of the real build, exercises only
 * hw_tts_init()/hw_tts_speak()/hw_tts_shutdown() in isolation, away from
 * ncurses/wolfSSL/the rest of client.c's threads, to isolate whether a
 * bug is in hw_tts.c itself or something about the full client's
 * runtime environment. Temporary - delete once the real bug is found. */
#include "hw_tts.h"
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("calling hw_tts_init()...\n");
    int rc = hw_tts_init();
    printf("hw_tts_init() returned %d\n", rc);

    printf("calling hw_tts_speak()...\n");
    hw_tts_speak("This is a diagnostic test of the resident pipeline.");

    printf("sleeping 5s to let it process...\n");
    sleep(5);

    printf("calling hw_tts_shutdown()...\n");
    hw_tts_shutdown();

    printf("done\n");
    return 0;
}

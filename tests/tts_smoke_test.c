/* Standalone diagnostic - NOT part of the real build. Exercises hw_tts_init()/hw_tts_speak()/hw_tts_shutdown() in isolation. Temporary - delete once fixed. */
#include "hw_tts.h"
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("calling hw_tts_init()...\n");
    int rc = hw_tts_init();
    printf("hw_tts_init() returned %d\n", rc);

    printf("calling hw_tts_speak() with a long sentence...\n");
    hw_tts_speak("This is a genuinely long test sentence with more than "
                 "ten words in it to see if the speech synthesis engine "
                 "cuts it off early or reads the whole thing all the way "
                 "to the end.");

    printf("sleeping 12s to let it process...\n");
    sleep(12);

    printf("calling hw_tts_shutdown()...\n");
    hw_tts_shutdown();

    printf("done\n");
    return 0;
}

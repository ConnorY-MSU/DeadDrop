/* Standalone diagnostic - NOT part of the real build. Speaks a phrase at each volume level for audible verification. Stop the live service first (its piper/aplay pipeline would conflict). Temporary - delete once done. */
#include "hw_tts.h"
#include "hw_volume.h"
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int levels[] = { 25, 50, 75 };
    size_t i;
    int before = hw_volume_get();

    printf("original volume: %d%%\n", before);

    printf("calling hw_tts_init()...\n");
    printf("hw_tts_init() returned %d\n", hw_tts_init());

    for (i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        int level = levels[i];
        char phrase[64];

        printf("--- setting volume to %d%% ---\n", level);
        printf("hw_volume_set(%d) returned %d\n", level,
               hw_volume_set(level));

        snprintf(phrase, sizeof(phrase),
                 "Testing volume at %d percent.", level);
        printf("speaking: \"%s\"\n", phrase);
        hw_tts_speak(phrase);

        sleep(4);
    }

    printf("restoring original volume (%d%%)...\n", before);
    hw_volume_set(before < 0 ? 100 : before);

    printf("calling hw_tts_shutdown()...\n");
    hw_tts_shutdown();

    printf("done\n");
    return 0;
}

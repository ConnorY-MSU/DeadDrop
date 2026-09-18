/* Standalone diagnostic - NOT part of the real build. Exercises hw_volume_get()/hw_volume_set() in isolation. Temporary - delete once confirmed working end-to-end. */
#include "hw_volume.h"
#include <stdio.h>

int main(void)
{
    int before, after;
    int levels[] = { 25, 50, 75 };
    size_t i;
    int all_pass = 1;

    printf("calling hw_volume_get() (before)...\n");
    before = hw_volume_get();
    printf("hw_volume_get() returned %d\n", before);

    for (i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        int target = levels[i];
        int set_rc = hw_volume_set(target);
        printf("--- level %d%% ---\n", target);
        printf("hw_volume_set(%d) returned %d\n", target, set_rc);

        after = hw_volume_get();
        printf("hw_volume_get() returned %d\n", after);

        if (set_rc != 0 || after != target) {
            printf("FAIL at %d%%: expected %d after set, got %d "
                   "(set_rc=%d)\n", target, target, after, set_rc);
            all_pass = 0;
        } else {
            printf("PASS at %d%%\n", target);
        }
    }

    printf("calling hw_volume_set(%d) to restore original...\n", before);
    printf("hw_volume_set(%d) returned %d\n", before,
           hw_volume_set(before < 0 ? 100 : before));

    if (!all_pass) {
        printf("OVERALL: FAIL\n");
        return 1;
    }
    printf("OVERALL: PASS\n");
    return 0;
}

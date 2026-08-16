#include "debug.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");
}
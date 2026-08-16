#ifndef DEBUG_H
#define DEBUG_H
#include <stdint.h>
#include <stddef.h>
void print_hex(const char *label, const uint8_t *data, size_t len);
#endif
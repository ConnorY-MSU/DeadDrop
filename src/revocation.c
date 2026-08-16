#include <stdio.h>
#include <string.h>
#include <strings.h>  
#include <ctype.h>     

#include "revocation.h"

#define MAX_REVOKED_SERIALS 64
#define MAX_SERIAL_LEN      64  

static char revoked_serials[MAX_REVOKED_SERIALS][MAX_SERIAL_LEN];
static int  revoked_count = 0;
static int  loaded_ok = 0;


static void to_upper_in_place(char *s)
{
    for (; *s; s++) {
        *s = (char)toupper((unsigned char)*s);
    }
}

static void strip_trailing_whitespace(char *s)
{
    size_t len = strlen(s);
    while (len > 0 &&
           (s[len - 1] == '\n' || s[len - 1] == '\r' ||
            s[len - 1] == ' '  || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

int revocation_load(const char *filepath)
{
    FILE *fp;
    char line[MAX_SERIAL_LEN];
    revoked_count = 0;
    loaded_ok = 0;

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        strip_trailing_whitespace(line);

        if (line[0] == '\0') {
            continue;
        }

        if (revoked_count >= MAX_REVOKED_SERIALS) {
            fprintf(stderr,
                "revocation_load: warning - revoked list exceeds "
                "MAX_REVOKED_SERIALS (%d), truncating\n",
                MAX_REVOKED_SERIALS);
            break;
        }

        strncpy(revoked_serials[revoked_count], line, MAX_SERIAL_LEN - 1);
        revoked_serials[revoked_count][MAX_SERIAL_LEN - 1] = '\0';
        to_upper_in_place(revoked_serials[revoked_count]);

        revoked_count++;
    }

    fclose(fp);
    loaded_ok = 1;
    return 0;
}

int revocation_is_revoked(const char *serial_hex)
{
    char query[MAX_SERIAL_LEN];
    int i;

    if (!loaded_ok) {
        return 1;
    }

    if (serial_hex == NULL) {
        return 1;
    }

    strncpy(query, serial_hex, MAX_SERIAL_LEN - 1);
    query[MAX_SERIAL_LEN - 1] = '\0';
    to_upper_in_place(query);

    for (i = 0; i < revoked_count; i++) {
        if (strcmp(query, revoked_serials[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

void revocation_free(void)
{
    revoked_count = 0;
    loaded_ok = 0;
}
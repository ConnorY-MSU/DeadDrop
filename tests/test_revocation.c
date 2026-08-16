#include <stdio.h>
#include <string.h>
#include "revocation.h"

static int all_pass = 1;

static void check(const char *name, int actual, int expected) {
    int ok = (actual == expected);
    printf("[%s] %s (got %d, expected %d)\n", ok ? "PASS" : "FAIL", name, actual, expected);
    if (!ok) all_pass = 0;
}

int main(void) {
    /* Real serials from securelink-pki, per PKI_SETUP.md */
    const char *server_serial = "68A7E95F14813C60A047706956F72BA0CCCC83F8";
    const char *client_serial = "68A7E95F14813C60A047706956F72BA0CCCC83F9";
    const char *server_serial_lower = "68a7e95f14813c60a047706956f72ba0cccc83f8";

    /* Fail-closed check: before any load, everything should be treated as revoked */
    check("fails closed before revocation_load() is called", revocation_is_revoked(server_serial), 1);

    /* Write a temp revoked-list file containing ONLY the server's serial */
    FILE *fp = fopen("test_revoked_list.txt", "w");
    fprintf(fp, "%s\n", server_serial);
    fclose(fp);

    int load_result = revocation_load("test_revoked_list.txt");
    check("revocation_load() succeeds on a valid file", load_result, 0);

    check("revoked serial (server) is detected as revoked", revocation_is_revoked(server_serial), 1);
    check("non-revoked serial (client) is NOT flagged as revoked", revocation_is_revoked(client_serial), 0);
    check("case-insensitive match (lowercase input)", revocation_is_revoked(server_serial_lower), 1);
    check("NULL input fails closed", revocation_is_revoked(NULL), 1);

    revocation_free();
    check("fails closed again after revocation_free()", revocation_is_revoked(server_serial), 1);

    check("revocation_load() fails cleanly on a missing file", revocation_load("does_not_exist.txt"), -1);

    remove("test_revoked_list.txt");

    printf("\n%s\n", all_pass ? "ALL VECTORS PASSED" : "SOME VECTORS FAILED");
    return all_pass ? 0 : 1;
}

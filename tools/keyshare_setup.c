/* keyshare_setup.c - one-time dev-machine tool generating K/R/share-pair material for the mutual key-share scheme. See COMMENT_ARCHIVE.md for usage/output details. */

#ifdef _WIN32
#define _CRT_RAND_S /* must be defined before stdlib.h is first included to declare rand_s() */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes128.h"

#define KEYSHARE_LEN 16
#define MAX_KEY_FILE_SIZE 8192 /* generous - a real PEM RSA/EC private key is well under this */

static int fill_random(uint8_t *buf, size_t len)
{
#ifdef __linux__
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return -1;
    }
    {
        size_t got = fread(buf, 1, len, f);
        fclose(f);
        return (got == len) ? 0 : -1;
    }
#elif defined(_WIN32)
    /* rand_s() is a real OS-backed CSPRNG, unlike rand() used elsewhere for non-security-critical purposes. */
    {
        size_t i;
        for (i = 0; i + 4 <= len; i += 4) {
            unsigned int r;
            if (rand_s(&r) != 0) {
                return -1;
            }
            memcpy(buf + i, &r, 4);
        }
        if (i < len) {
            unsigned int r;
            if (rand_s(&r) != 0) {
                return -1;
            }
            memcpy(buf + i, &r, len - i);
        }
    }
    return 0;
#else
    (void)buf;
    (void)len;
    return -1; /* no known-good CSPRNG on this platform - fail loudly rather than produce weak key material */
#endif
}

static void xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    size_t n;

    if (fp == NULL) {
        return -1;
    }
    n = fwrite(data, 1, len, fp);
    fclose(fp);
    return (n == len) ? 0 : -1;
}

int main(int argc, char *argv[])
{
    const char *device_name;
    const char *input_pem_path;
    const char *output_dir;
    char path_buf[600];

    uint8_t pem_buf[MAX_KEY_FILE_SIZE];
    long pem_len;
    FILE *fp;

    uint8_t K[KEYSHARE_LEN];
    uint8_t R[KEYSHARE_LEN];
    uint8_t share_remote[KEYSHARE_LEN];
    uint8_t round_key[AES128_ROUND_KEY_SIZE];
    uint8_t zero_counter[16];

    if (argc != 4) {
        fprintf(stderr,
            "Usage: %s <device_name> <input_private_key.pem> <output_dir>\n",
            argv[0]);
        return 1;
    }
    device_name = argv[1];
    input_pem_path = argv[2];
    output_dir = argv[3];

    /* Read the plaintext PEM key - exists only transiently on the dev machine; never copied onto either Pi in this form. */
    fp = fopen(input_pem_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Could not open %s\n", input_pem_path);
        return 1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    pem_len = ftell(fp);
    if (pem_len <= 0 || (size_t)pem_len > sizeof(pem_buf)) {
        fprintf(stderr, "Key file size out of expected range\n");
        fclose(fp);
        return 1;
    }
    rewind(fp);
    if (fread(pem_buf, 1, (size_t)pem_len, fp) != (size_t)pem_len) {
        fclose(fp);
        return 1;
    }
    fclose(fp);

    if (fill_random(K, sizeof(K)) != 0 || fill_random(R, sizeof(R)) != 0) {
        fprintf(stderr, "Failed to generate random key material\n");
        return 1;
    }
    xor_bytes(share_remote, K, R, KEYSHARE_LEN);

    /* Fixed all-zero counter is safe because K is single-use - see keyshare.h. */
    memset(zero_counter, 0, sizeof(zero_counter));
    aes128_key_expansion(K, round_key);
    aes128_ctr_xcrypt(round_key, zero_counter, pem_buf, pem_buf, (size_t)pem_len);

    snprintf(path_buf, sizeof(path_buf), "%s/%s_key.enc", output_dir, device_name);
    if (write_file(path_buf, pem_buf, (size_t)pem_len) != 0) {
        fprintf(stderr, "Failed to write %s\n", path_buf);
        return 1;
    }
    printf("Wrote %s (goes on %s)\n", path_buf, device_name);

    snprintf(path_buf, sizeof(path_buf), "%s/%s_share_local.bin", output_dir,
             device_name);
    if (write_file(path_buf, R, sizeof(R)) != 0) {
        fprintf(stderr, "Failed to write %s\n", path_buf);
        return 1;
    }
    printf("Wrote %s (goes on %s)\n", path_buf, device_name);

    snprintf(path_buf, sizeof(path_buf), "%s/%s_share_remote.bin", output_dir,
             device_name);
    if (write_file(path_buf, share_remote, sizeof(share_remote)) != 0) {
        fprintf(stderr, "Failed to write %s\n", path_buf);
        return 1;
    }
    printf("Wrote %s (this is %s's CUSTODY-SHARE - it goes on the OTHER "
           "device, not %s itself)\n", path_buf, device_name, device_name);

    /* Zero the real key material out of this process's memory before exiting - it already did its job. */
    memset(K, 0, sizeof(K));
    memset(R, 0, sizeof(R));
    memset(pem_buf, 0, sizeof(pem_buf));
    memset(round_key, 0, sizeof(round_key));

    printf("\nDone. Reminder: %s_key.enc and %s_share_local.bin go on "
           "%s itself; %s_share_remote.bin goes on %s's PAIRED device "
           "instead. Delete the plaintext input PEM key (%s) once both "
           "devices have their files - it should not remain on this "
           "machine any longer than necessary either.\n",
           device_name, device_name, device_name, device_name,
           device_name, input_pem_path);

    return 0;
}

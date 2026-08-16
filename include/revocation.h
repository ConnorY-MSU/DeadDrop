#ifndef REVOCATION_H
#define REVOCATION_H

int revocation_load(const char *filepath);

int revocation_is_revoked(const char *serial_hex);

void revocation_free(void);

#endif // REVOCATION_H
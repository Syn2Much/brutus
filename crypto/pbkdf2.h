#ifndef BRUTUS_PBKDF2_H
#define BRUTUS_PBKDF2_H
#include <stdint.h>
#include <stddef.h>

void pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                   const uint8_t *salt, size_t salt_len,
                   int iterations,
                   uint8_t *out, size_t out_len);
#endif

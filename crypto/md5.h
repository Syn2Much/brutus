#ifndef ARMSCAN_MD5_H
#define ARMSCAN_MD5_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buffer[64];
} md5_ctx;

void md5_init(md5_ctx *c);
void md5_update(md5_ctx *c, const uint8_t *data, size_t len);
void md5_final(md5_ctx *c, uint8_t out[16]);
void md5_hex(const uint8_t *data, size_t len, char out[33]);
#endif

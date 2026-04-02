#ifndef ARMSCAN_SHA1_H
#define ARMSCAN_SHA1_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buffer[64];
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx *c, uint8_t out[20]);
void sha1_oneshot(const uint8_t *data, size_t len, uint8_t out[20]);

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t out[20]);
#endif

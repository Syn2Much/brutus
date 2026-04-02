#ifndef BRUTUS_SHA256_H
#define BRUTUS_SHA256_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint8_t  buf[64];
    size_t   buf_len;
    uint64_t total;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *c);
void sha256_update(sha256_ctx_t *c, const uint8_t *data, size_t len);
void sha256_finish(sha256_ctx_t *c, uint8_t out[32]);
void sha256_oneshot(const uint8_t *data, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[32]);
#endif

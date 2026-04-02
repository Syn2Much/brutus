#ifndef ARMSCAN_AES128_H
#define ARMSCAN_AES128_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t rk[44];
    uint8_t  ctr[16];
    uint8_t  ks[16];
    int      ks_pos;
} aes128ctr_t;

void aes128_expand_key(const uint8_t key[16], uint32_t rk[44]);
void aes128_encrypt_block(const uint32_t rk[44], uint8_t block[16]);
void aes128ctr_init(aes128ctr_t *c, const uint8_t key[16], const uint8_t iv[16]);
void aes128ctr_crypt(aes128ctr_t *c, uint8_t *data, size_t len);
#endif

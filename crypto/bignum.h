#ifndef BRUTUS_BIGNUM_H
#define BRUTUS_BIGNUM_H
#include <stdint.h>

#define BN_MAX 520

typedef struct {
    uint8_t d[BN_MAX];
    int     len;
} bn_t;

void bn_zero(bn_t *a);
void bn_from_bytes(bn_t *a, const uint8_t *data, int len);
void bn_from_u32(bn_t *a, uint32_t v);
int  bn_to_bytes(const bn_t *a, uint8_t *out, int max);
int  bn_cmp(const bn_t *a, const bn_t *b);
void bn_copy(bn_t *dst, const bn_t *src);
void bn_add(bn_t *a, const bn_t *b);
void bn_sub(bn_t *a, const bn_t *b);
void bn_shl1(bn_t *a);
void bn_mod(bn_t *r, const bn_t *a, const bn_t *m);
void bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m);
#endif

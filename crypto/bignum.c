#include "bignum.h"
#include <string.h>

void bn_zero(bn_t *a) { memset(a->d, 0, BN_MAX); a->len = 1; }

void bn_from_bytes(bn_t *a, const uint8_t *data, int len) {
    int off;
    bn_zero(a);
    if (len > BN_MAX) len = BN_MAX;
    off = BN_MAX - len;
    memcpy(a->d + off, data, len);
    a->len = len;
}

void bn_from_u32(bn_t *a, uint32_t v) {
    bn_zero(a);
    a->d[BN_MAX-1] = (uint8_t)(v & 0xFF);
    a->d[BN_MAX-2] = (uint8_t)((v >> 8) & 0xFF);
    a->d[BN_MAX-3] = (uint8_t)((v >> 16) & 0xFF);
    a->d[BN_MAX-4] = (uint8_t)((v >> 24) & 0xFF);
    a->len = 4;
}

int bn_to_bytes(const bn_t *a, uint8_t *out, int max) {
    int start = 0, len, i;
    /* scan from MSB -- don't trust a->len, it drifts through mul/mod */
    while (start < BN_MAX - 1 && a->d[start] == 0) start++;
    len = BN_MAX - start;
    if (len > max) return -1;
    for (i = 0; i < len; i++) out[i] = a->d[start + i];
    return len;
}

int bn_cmp(const bn_t *a, const bn_t *b) {
    int i;
    for (i = 0; i < BN_MAX; i++) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

void bn_copy(bn_t *dst, const bn_t *src) {
    memcpy(dst->d, src->d, BN_MAX);
    dst->len = src->len;
}

/* a = a + b (in place, no overflow check needed for our sizes) */
void bn_add(bn_t *a, const bn_t *b) {
    int i;
    uint16_t carry = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        uint16_t s = (uint16_t)a->d[i] + (uint16_t)b->d[i] + carry;
        a->d[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
    if (a->len < b->len) a->len = b->len;
}

/* a = a - b (assumes a >= b) */
void bn_sub(bn_t *a, const bn_t *b) {
    int i;
    int16_t borrow = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        int16_t s = (int16_t)a->d[i] - (int16_t)b->d[i] - borrow;
        if (s < 0) { s += 256; borrow = 1; }
        else { borrow = 0; }
        a->d[i] = (uint8_t)s;
    }
}

/* a = a << 1 (left shift by 1 bit) */
void bn_shl1(bn_t *a) {
    int i;
    uint8_t carry = 0;
    for (i = BN_MAX - 1; i >= 0; i--) {
        uint8_t nc = (a->d[i] >> 7) & 1;
        a->d[i] = (uint8_t)((a->d[i] << 1) | carry);
        carry = nc;
    }
}

/* r = a mod m (using repeated subtraction -- fine for DH sizes) */
void bn_mod(bn_t *r, const bn_t *a, const bn_t *m) {
    bn_t shifted_m;
    int bit, i;
    bn_copy(r, a);

    /* Find highest bit of r */
    bit = 0;
    for (i = 0; i < BN_MAX; i++) {
        if (r->d[i]) { bit = (BN_MAX - i) * 8; break; }
    }
    if (bit == 0) return;

    /* Shift m up to align with r, then subtract down */
    bn_copy(&shifted_m, m);
    {
        int m_bit = 0;
        for (i = 0; i < BN_MAX; i++) {
            if (shifted_m.d[i]) { m_bit = (BN_MAX - i) * 8; break; }
        }
        while (m_bit < bit) { bn_shl1(&shifted_m); m_bit++; }
    }

    while (bn_cmp(&shifted_m, m) >= 0) {
        if (bn_cmp(r, &shifted_m) >= 0)
            bn_sub(r, &shifted_m);
        /* shift m right by 1 */
        {
            int j;
            uint8_t carry = 0;
            for (j = 0; j < BN_MAX; j++) {
                uint8_t nc = (shifted_m.d[j] & 1) << 7;
                shifted_m.d[j] = (shifted_m.d[j] >> 1) | carry;
                carry = nc;
            }
        }
    }
}

/* r = (a * b) mod m */
void bn_mulmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m) {
    bn_t acc, base;
    int i, j;
    bn_zero(&acc);
    bn_copy(&base, a);
    bn_mod(&base, &base, m);

    /* Iterate bits of b from LSB to MSB */
    for (i = BN_MAX - 1; i >= 0; i--) {
        for (j = 0; j < 8; j++) {
            if ((b->d[i] >> j) & 1) {
                bn_add(&acc, &base);
                if (bn_cmp(&acc, m) >= 0) bn_sub(&acc, m);
            }
            bn_shl1(&base);
            if (bn_cmp(&base, m) >= 0) bn_sub(&base, m);
        }
    }
    bn_copy(r, &acc);
}

/* r = base^exp mod m (square-and-multiply) */
void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m) {
    bn_t result, b;
    int i, j, started;
    bn_from_u32(&result, 1);
    bn_copy(&b, base);
    bn_mod(&b, &b, m);

    started = 0;
    for (i = 0; i < BN_MAX; i++) {
        for (j = 7; j >= 0; j--) {
            if (!started) {
                if ((exp->d[i] >> j) & 1) {
                    bn_copy(&result, &b);
                    started = 1;
                }
                continue;
            }
            bn_mulmod(&result, &result, &result, m);
            if ((exp->d[i] >> j) & 1) {
                bn_mulmod(&result, &result, &b, m);
            }
        }
    }
    bn_copy(r, &result);
}

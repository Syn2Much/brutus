/* curve25519.c -- X25519 Diffie-Hellman (RFC 7748)
   GF(2^255-19) with 16 x int64_t limbs (TweetNaCl representation). */

#include "curve25519.h"
#include <string.h>
#include <stdint.h>

typedef long long i64;
typedef i64 gf[16];

static void car(gf o) {
    int i;
    i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel(gf p, gf q, int b) {
    i64 t, c = ~((i64)b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack(uint8_t o[32], const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car(t); car(t); car(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xFFFF;
        sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xFF);
    }
}

static void unpack(gf o, const uint8_t n[32]) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7FFF;
}

static void gf_add(gf o, const gf a, const gf b) {
    int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b) {
    int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void gf_mul(gf o, const gf a, const gf b) {
    i64 t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car(o);
    car(o);
}

static void gf_sq(gf o, const gf a) { gf_mul(o, a, a); }

static void gf_inv(gf o, const gf a) {
    gf c;
    int i;
    for (i = 0; i < 16; i++) c[i] = a[i];
    for (i = 253; i >= 0; i--) {
        gf_sq(c, c);
        if (i != 2 && i != 4) gf_mul(c, c, a);
    }
    for (i = 0; i < 16; i++) o[i] = c[i];
}

/* RFC 7748 scalar multiplication -- direct translation */
static void scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    gf u, x2, z2, x3, z3;
    gf tA, tAA, tB, tBB, tE, tC, tD, tDA, tCB;
    gf t0, t1;
    int i, swap, bit;

    /* a24 = (486662 - 2) / 4 = 121665 (used with AA, not BB) */
    static const gf a24 = {0xDB41, 1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] = (e[31] & 127) | 64;

    unpack(u, point);

    /* x2 = 1, z2 = 0, x3 = u, z3 = 1 */
    memset(x2, 0, sizeof(gf)); x2[0] = 1;
    memset(z2, 0, sizeof(gf));
    for (i = 0; i < 16; i++) x3[i] = u[i];
    memset(z3, 0, sizeof(gf)); z3[0] = 1;

    swap = 0;
    for (i = 254; i >= 0; i--) {
        bit = (e[i >> 3] >> (i & 7)) & 1;
        swap ^= bit;
        sel(x2, x3, swap);
        sel(z2, z3, swap);
        swap = bit;

        gf_add(tA, x2, z2);      /* A = x2 + z2       */
        gf_sq(tAA, tA);          /* AA = A^2           */
        gf_sub(tB, x2, z2);      /* B = x2 - z2       */
        gf_sq(tBB, tB);          /* BB = B^2           */
        gf_sub(tE, tAA, tBB);    /* E = AA - BB        */
        gf_add(tC, x3, z3);      /* C = x3 + z3       */
        gf_sub(tD, x3, z3);      /* D = x3 - z3       */
        gf_mul(tDA, tD, tA);     /* DA = D * A         */
        gf_mul(tCB, tC, tB);     /* CB = C * B         */

        /* x3 = (DA + CB)^2 */
        gf_add(t0, tDA, tCB);
        gf_sq(x3, t0);

        /* z3 = u * (DA - CB)^2 */
        gf_sub(t0, tDA, tCB);
        gf_sq(t1, t0);
        gf_mul(z3, u, t1);

        /* x2 = AA * BB */
        gf_mul(x2, tAA, tBB);

        /* z2 = E * (AA + a24 * E) */
        gf_mul(t0, a24, tE);     /* a24 * E            */
        gf_add(t0, tAA, t0);     /* AA + a24*E         */
        gf_mul(z2, tE, t0);      /* E * (AA + a24*E)   */
    }

    sel(x2, x3, swap);
    sel(z2, z3, swap);

    gf_inv(t0, z2);
    gf_mul(t1, x2, t0);
    pack(out, t1);
}

void x25519(uint8_t shared[32], const uint8_t scalar[32], const uint8_t point[32]) {
    scalarmult(shared, scalar, point);
}

void x25519_public(uint8_t pub[32], const uint8_t scalar[32]) {
    static const uint8_t basepoint[32] = {9};
    scalarmult(pub, scalar, basepoint);
}

#include "sha256.h"
#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, S1, ch, t1, S0, mj, t2, s0, s1;
    int i;
    for (i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++) {
        s0 = rotr(W[i-15],7) ^ rotr(W[i-15],18) ^ (W[i-15]>>3);
        s1 = rotr(W[i-2],17) ^ rotr(W[i-2],19) ^ (W[i-2]>>10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (i = 0; i < 64; i++) {
        S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K256[i] + W[i];
        S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        mj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void sha256_init(sha256_ctx_t* c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->buf_len = 0; c->total = 0;
}

void sha256_update(sha256_ctx_t* c, const uint8_t* data, size_t len) {
    size_t off = 0, need, take;
    c->total += len;
    if (c->buf_len > 0) {
        need = 64 - c->buf_len;
        take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take; off += take;
        if (c->buf_len == 64) { sha256_transform(c->state, c->buf); c->buf_len = 0; }
    }
    while (off + 64 <= len) { sha256_transform(c->state, data + off); off += 64; }
    if (off < len) { c->buf_len = len - off; memcpy(c->buf, data + off, c->buf_len); }
}

void sha256_finish(sha256_ctx_t* c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, zero = 0;
    uint8_t len_be[8];
    int i;
    sha256_update(c, &pad, 1);
    while (c->buf_len != 56) sha256_update(c, &zero, 1);
    for (i = 7; i >= 0; i--) { len_be[i] = (uint8_t)(bits & 0xFF); bits >>= 8; }
    sha256_update(c, len_be, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]=(uint8_t)(c->state[i]>>24); out[i*4+1]=(uint8_t)(c->state[i]>>16);
        out[i*4+2]=(uint8_t)(c->state[i]>>8); out[i*4+3]=(uint8_t)(c->state[i]);
    }
}

void sha256_oneshot(const uint8_t* data, size_t len, uint8_t out[32]) {
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_finish(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[32])
{
    sha256_ctx_t ctx;
    uint8_t k_pad[64];
    uint8_t inner_hash[32];
    size_t i;

    /* If key > 64 bytes, hash it first */
    uint8_t key_block[64];
    memset(key_block, 0, 64);
    if (key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_finish(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Inner hash: SHA256((key ^ ipad) || message) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x36;
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, msg, msg_len);
    sha256_finish(&ctx, inner_hash);

    /* Outer hash: SHA256((key ^ opad) || inner_hash) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x5c;
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_finish(&ctx, out);

    memset(key_block, 0, 64);
    memset(k_pad, 0, 64);
    memset(inner_hash, 0, 32);
}

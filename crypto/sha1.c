#include "sha1.h"
#include <string.h>

#define SHA1_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void sha1_transform(sha1_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[80], a,b,c,d,e,f,k,temp; int i;
    for(i=0;i<16;i++) w[i]=((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for(i=16;i<80;i++) w[i]=SHA1_ROTL(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];e=ctx->state[4];
    for(i=0;i<80;i++){
        if(i<20){f=(b&c)|((~b)&d);k=0x5A827999;}
        else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
        else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
        else{f=b^c^d;k=0xCA62C1D6;}
        temp=SHA1_ROTL(a,5)+f+e+k+w[i];e=d;d=c;c=SHA1_ROTL(b,30);b=a;a=temp;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;ctx->state[4]+=e;
}

void sha1_init(sha1_ctx *c){c->state[0]=0x67452301;c->state[1]=0xEFCDAB89;c->state[2]=0x98BADCFE;c->state[3]=0x10325476;c->state[4]=0xC3D2E1F0;c->count=0;}

void sha1_update(sha1_ctx *c,const uint8_t *d,size_t l){size_t i;size_t idx=c->count%64;c->count+=l;for(i=0;i<l;i++){c->buffer[idx++]=d[i];if(idx==64){sha1_transform(c,c->buffer);idx=0;}}}

void sha1_final(sha1_ctx *c,uint8_t h[20]){
    uint64_t bits=c->count*8;uint8_t p=0x80;sha1_update(c,&p,1);p=0;
    while(c->count%64!=56)sha1_update(c,&p,1);
    {uint8_t b[8];int i;for(i=0;i<8;i++)b[i]=(uint8_t)(bits>>((7-i)*8));sha1_update(c,b,8);}
    {int i;for(i=0;i<5;i++){h[i*4]=(uint8_t)(c->state[i]>>24);h[i*4+1]=(uint8_t)(c->state[i]>>16);h[i*4+2]=(uint8_t)(c->state[i]>>8);h[i*4+3]=(uint8_t)c->state[i];}}
}

void sha1_oneshot(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx ctx; sha1_init(&ctx); sha1_update(&ctx, data, len); sha1_final(&ctx, out);
}

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len,
               uint8_t out[20])
{
    sha1_ctx ctx;
    uint8_t k_pad[64];
    uint8_t inner_hash[20];
    size_t i;

    /* If key > 64 bytes, hash it first */
    uint8_t key_block[64];
    memset(key_block, 0, 64);
    if (key_len > 64) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Inner hash: SHA1((key ^ ipad) || message) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x36;
    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, 64);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, inner_hash);

    /* Outer hash: SHA1((key ^ opad) || inner_hash) */
    for (i = 0; i < 64; i++) k_pad[i] = key_block[i] ^ 0x5c;
    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, 64);
    sha1_update(&ctx, inner_hash, 20);
    sha1_final(&ctx, out);

    memset(key_block, 0, 64);
    memset(k_pad, 0, 64);
    memset(inner_hash, 0, 20);
}

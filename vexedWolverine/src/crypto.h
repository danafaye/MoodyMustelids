#ifndef VW_CRYPTO_H
#define VW_CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
static uint32_t v_rol(uint32_t x, unsigned n) { n &= 31; return (x << n) | (x >> ((32-n)&31)); }
static uint32_t v_ror(uint32_t x, unsigned n) { return v_rol(x, 32-(n&31)); }
static uint32_t v_ld(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static void v_st(uint8_t *p,uint32_t x) { p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);p[3]=(uint8_t)(x>>24); }
static uint32_t v_fnv(const uint8_t *p,size_t n,uint32_t h) { while(n--) h=(h^*p++)*16777619u; return h; }
static void v_zero(void *p,size_t n) { volatile uint8_t *b=(volatile uint8_t*)p; while(n--) *b++=0; }
static void v_qr(uint32_t *s,unsigned a,unsigned b,unsigned c,unsigned d) {
    s[a]+=s[b];s[d]=v_rol(s[d]^s[a],16);s[c]+=s[d];s[b]=v_rol(s[b]^s[c],12);
    s[a]+=s[b];s[d]=v_rol(s[d]^s[a],8);s[c]+=s[d];s[b]=v_rol(s[b]^s[c],7);
}
static void v_stream(const uint8_t key[32],const uint8_t nonce[12],uint8_t *p,size_t n) {
    uint32_t initial[16],s[16],counter=1; uint8_t block[64]; size_t j; unsigned i,r;
    initial[0]=0x61707865;initial[1]=0x3320646e;initial[2]=0x79622d32;initial[3]=0x6b206574;
    for(i=0;i<8;i++) initial[4+i]=v_ld(key+i*4);
    for(i=0;i<3;i++) initial[13+i]=v_ld(nonce+i*4);
    while(n) {
        initial[12]=counter++;memcpy(s,initial,sizeof s);
        for(r=0;r<10;r++) {
            v_qr(s,0,4,8,12);v_qr(s,1,5,9,13);v_qr(s,2,6,10,14);v_qr(s,3,7,11,15);
            v_qr(s,0,5,10,15);v_qr(s,1,6,11,12);v_qr(s,2,7,8,13);v_qr(s,3,4,9,14);
        }
        for(i=0;i<16;i++) v_st(block+i*4,s[i]+initial[i]);
        j=n<64?n:64;for(i=0;i<j;i++) p[i]^=block[i];p+=j;n-=j;
    }
    v_zero(s,sizeof s);v_zero(block,sizeof block);v_zero(initial,sizeof initial);
}
typedef struct { uint32_t h[8];uint64_t count;uint8_t buf[64];size_t used; } VHash;
static void v_hash_block(VHash *ctx,const uint8_t *data) {
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;unsigned i;
    for(i=0;i<16;i++)w[i]=(uint32_t)data[4*i]<<24|(uint32_t)data[4*i+1]<<16|(uint32_t)data[4*i+2]<<8|data[4*i+3];
    for(i=16;i<64;i++)w[i]=w[i-16]+(v_ror(w[i-15],7)^v_ror(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(v_ror(w[i-2],17)^v_ror(w[i-2],19)^(w[i-2]>>10));
    a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
    for(i=0;i<64;i++){t1=h+(v_ror(e,6)^v_ror(e,11)^v_ror(e,25))+((e&f)^((~e)&g))+k[i]+w[i];t2=(v_ror(a,2)^v_ror(a,13)^v_ror(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;ctx->h[4]+=e;ctx->h[5]+=f;ctx->h[6]+=g;ctx->h[7]+=h;v_zero(w,sizeof w);
}
static void v_hash_init(VHash *ctx) {
    static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(ctx->h,iv,sizeof iv);ctx->count=0;ctx->used=0;
}
static void v_hash_add(VHash *ctx,const void *data,size_t n) {
    const uint8_t *p=(const uint8_t*)data;size_t take;ctx->count+=n;
    while(n){take=64-ctx->used;if(take>n)take=n;memcpy(ctx->buf+ctx->used,p,take);ctx->used+=take;p+=take;n-=take;if(ctx->used==64){v_hash_block(ctx,ctx->buf);ctx->used=0;}}
}
static void v_hash_end(VHash *ctx,uint8_t out[32]) {
    uint64_t bits=ctx->count*8;uint8_t pad[128]={0x80};size_t n=ctx->used<56?56-ctx->used:120-ctx->used;unsigned i;
    for(i=0;i<8;i++)pad[n+i]=(uint8_t)(bits>>(56-8*i));
    v_hash_add(ctx,pad,n+8);
    for(i=0;i<8;i++){out[4*i]=(uint8_t)(ctx->h[i]>>24);out[4*i+1]=(uint8_t)(ctx->h[i]>>16);out[4*i+2]=(uint8_t)(ctx->h[i]>>8);out[4*i+3]=(uint8_t)ctx->h[i];}v_zero(ctx,sizeof *ctx);
}
static void v_hash(const void *p,size_t n,uint8_t out[32]) { VHash ctx;v_hash_init(&ctx);v_hash_add(&ctx,p,n);v_hash_end(&ctx,out); }
static void v_derive(const uint8_t root[32],uint8_t suffix,uint8_t key[32]) { VHash ctx;uint8_t tag[2]={'/',suffix};v_hash_init(&ctx);v_hash_add(&ctx,root,32);v_hash_add(&ctx,tag,2);v_hash_end(&ctx,key); }
#endif

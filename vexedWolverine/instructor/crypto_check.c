#include <stdio.h>
#include "../src/crypto.h"
static void emit(const uint8_t *p,size_t n){size_t i;for(i=0;i<n;i++)printf("%02x",p[i]);putchar('\n');}
int main(void){
    uint8_t out[32],key[32],nonce[12]={0,0,0,9,0,0,0,0x4a,0,0,0,0},stream[64]={0},longmsg[129];unsigned i;
    v_hash("abc",3,out);emit(out,32);
    for(i=0;i<sizeof longmsg;i++)longmsg[i]=(uint8_t)i;
    v_hash(longmsg,56,out);emit(out,32);v_hash(longmsg,64,out);emit(out,32);v_hash(longmsg,129,out);emit(out,32);
    for(i=0;i<32;i++)key[i]=(uint8_t)i;
    v_stream(key,nonce,stream,64);emit(stream,64);
    return v_fnv(out,32,1)==0?1:0;
}

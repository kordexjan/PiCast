/* Synthetic protocol-test bridge, never linked into the receiver. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "picast_pin.h"
#include <openssl/srp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void hex(const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
int main(void){
    struct pc_pin p={0};assert(pc_pin_begin(&p)==0);assert(pc_pin_begin(&p)==-1);
    char *n=BN_bn2hex(SRP_get_default_gN("2048")->N);char code[5];memcpy(code,p.code,sizeof(code));
    printf("%s %s\n",n,p.code);OPENSSL_free(n);fflush(stdout);
    for(unsigned step=0;step<32;step++){
        char line[8194];if(!fgets(line,sizeof(line),stdin))break;
        size_t bytes=strcspn(line,"\n")/2;assert(bytes<=4096);uint8_t input[4096],out[1024],own[32]={0};
        for(size_t i=0;i<bytes;i++){unsigned v;assert(sscanf(line+i*2,"%2x",&v)==1);input[i]=(uint8_t)v;}
        size_t written=0;
        if(pc_pin_request(&p,input,bytes,own,out,sizeof(out),&written)){
            /* Calls after completion are refused without erasing established
             * identity. A wrong code returns to the start until its limit. */
            assert(p.phase==0 || p.phase==1 || p.phase==4);
            assert(p.phase!=1 || !strcmp(p.code,code));
            puts("rejected");fflush(stdout);continue;
        }
        hex(out,written);putchar('\n');fflush(stdout);
        if(p.phase==4){uint8_t expected[32];memset(expected,0x42,32);assert(!memcmp(p.peer_key,expected,32));}
    }
    pc_pin_clear(&p);assert(!p.phase && !p.srp.private_state);return 0;
}

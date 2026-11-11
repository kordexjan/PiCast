/* Synthetic test keys only. Not linked into the receiver. */
#include "picast_mirror_crypto.h"
#include "picast.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){
    assert(argc==2);char *end=NULL;errno=0;uint64_t stream=strtoull(argv[1],&end,10);assert(!errno && end && !*end && argv[1][0]!='-');
    struct pc_mirror_cipher c={0};uint8_t media[16],ecdh[32],input[128],out[128];
    for(unsigned i=0;i<16;i++)media[i]=(uint8_t)i;
    for(unsigned i=0;i<32;i++)ecdh[i]=(uint8_t)(32+i);
    memset(out,0xa7,sizeof(out));
    assert(pc_mirror_cipher_update(&c,input,1,out,sizeof(out))==PC_INVALID);
    assert(pc_mirror_cipher_init(&c,media,ecdh,stream)==PC_OK);
    assert(pc_mirror_cipher_init(&c,media,ecdh,stream)==PC_INVALID);
    assert(pc_mirror_cipher_update(&c,input,17,out,16)==PC_INVALID && !c.bytes);
    assert(pc_mirror_cipher_update(&c,input,17,input+1,32)==PC_INVALID && !c.bytes);
    for(size_t i=0;i<sizeof(out);i++)assert(out[i]==0xa7);
    const size_t sizes[]={1,7,15,16,17,31,32,63,127};unsigned iteration=0;
    for(;;){
        size_t n=fread(input,1,sizes[iteration++%9],stdin);if(!n)break;
        if(iteration&1){assert(pc_mirror_cipher_update(&c,input,n,input,sizeof(input))==PC_OK);assert(fwrite(input,1,n,stdout)==n);}
        else {assert(pc_mirror_cipher_update(&c,input,n,out,sizeof(out))==PC_OK);assert(fwrite(out,1,n,stdout)==n);}
    }
    assert(!ferror(stdin));
    /* A 1080p mirror session passes 64 MiB in about two minutes (r167). */
    c.bytes=UINT64_C(1)<<40;assert(pc_mirror_cipher_update(&c,input,1,out,sizeof(out))==PC_OK);
    c.bytes=UINT64_MAX;assert(pc_mirror_cipher_update(&c,input,1,out,sizeof(out))==PC_INVALID);
    pc_mirror_cipher_clear(&c);assert(!c.context && !c.bytes);pc_mirror_cipher_clear(&c);return 0;
}

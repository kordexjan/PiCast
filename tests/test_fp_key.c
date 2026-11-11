#include "picast_fp_key.h"
#include "picast.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void){
    uint8_t m[164]={'F','P','L','Y',3,1,3,0,0,0,0,152},w[72]={'F','P','L','Y'},key[16],sentinel[16];
    memset(sentinel,0xa5,16);
    for(size_t n=0;n<200;n++){
        memcpy(key,sentinel,16);
        if(n!=164){assert(pc_fp_key_unwrap(m,n,w,72,key)==PC_INVALID);assert(!memcmp(key,sentinel,16));}
        if(n!=72){assert(pc_fp_key_unwrap(m,164,w,n,key)==PC_INVALID);assert(!memcmp(key,sentinel,16));}
    }
    for(unsigned mode=4;mode<256;mode++){
        m[12]=(uint8_t)mode;assert(pc_fp_key_unwrap(m,164,w,72,key)==PC_INVALID);
    }
    for(unsigned mode=0;mode<4;mode++){
        m[12]=(uint8_t)mode;
        for(unsigned k=0;k<8;k++){
            for(size_t j=13;j<164;j++)m[j]=(uint8_t)(j*17+k*31);
            for(size_t j=4;j<72;j++)w[j]=(uint8_t)(j*29+k);
            assert(pc_fp_key_unwrap(m,164,w,72,key)==PC_OK);
        }
    }
    assert(pc_fp_key_unwrap(NULL,164,w,72,key)==PC_INVALID);
    puts("PlayFair boundary: lengths, modes, four-mode sanitizer exercise passed (no correctness claim)");
}

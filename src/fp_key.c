#include "picast_fp_key.h"
#include "picast.h"
#include "playfair.h"
#include <openssl/crypto.h>
#include <string.h>
int pc_fp_key_unwrap(const uint8_t *message,size_t n,const uint8_t *wrapped,size_t wn,uint8_t out[16]) {
    static const uint8_t header[12]={'F','P','L','Y',3,1,3,0,0,0,0,152};
    if(!message || !wrapped || !out || n!=164 || wn!=72 ||
       memcmp(message,header,12) || message[12]>3 || memcmp(wrapped,"FPLY",4))return PC_INVALID;
    /* The upstream API accepts mutable pointers and uses word accesses.
     * Never expose packet storage or the caller's output directly. */
    _Alignas(16) uint8_t m[176]={0},w[80]={0},key[16]={0};
    memcpy(m,message,n);memcpy(w,wrapped,wn);
    playfair_decrypt(m,w,key);
    memcpy(out,key,16);
    OPENSSL_cleanse(m,sizeof(m));OPENSSL_cleanse(w,sizeof(w));OPENSSL_cleanse(key,sizeof(key));
    return PC_OK;
}

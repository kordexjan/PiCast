/* Original PiCast mirror-stream key derivation and continuous AES-CTR.
 * Protocol derivation described at https://github.com/FDH2/UxPlay/wiki/AirPlay2
 * (screen image data). OpenSSL supplies the cryptographic primitives. */
#include "picast_mirror_crypto.h"
#include "picast.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
void pc_mirror_cipher_clear(struct pc_mirror_cipher *c){
    if(!c)return;
    EVP_CIPHER_CTX_free(c->context);OPENSSL_cleanse(c,sizeof(*c));
}
static int sha512(const uint8_t *data,size_t size,uint8_t out[64]){
    unsigned n=0;return EVP_Digest(data,size,out,&n,EVP_sha512(),NULL)==1 && n==64;
}
int pc_mirror_cipher_init(struct pc_mirror_cipher *c,const uint8_t media[16],const uint8_t ecdh[32],uint64_t stream){
    if(!c || c->context || c->bytes || !media || !ecdh)return PC_INVALID;
    uint8_t material[48],folded[64],derived[2][64],input[96];int ok=0;
    memcpy(material,media,16);memcpy(material+16,ecdh,32);
    if(!sha512(material,sizeof(material),folded))goto done;
    const char *labels[]={"AirPlayStreamKey","AirPlayStreamIV"};
    for(unsigned i=0;i<2;i++){
        /* The full unsigned decimal representation matters for IDs >=2^63. */
        int n=snprintf((char *)input,sizeof(input),"%s%" PRIu64,labels[i],stream);
        if(n<1 || (size_t)n+16>sizeof(input))goto done;
        memcpy(input+n,folded,16);
        if(!sha512(input,(size_t)n+16,derived[i]))goto done;
    }
    c->context=EVP_CIPHER_CTX_new();
    if(!c->context || EVP_DecryptInit_ex(c->context,EVP_aes_128_ctr(),NULL,derived[0],derived[1])!=1)goto done;
    ok=1;
done:
    OPENSSL_cleanse(material,sizeof(material));OPENSSL_cleanse(folded,sizeof(folded));
    OPENSSL_cleanse(derived,sizeof(derived));OPENSSL_cleanse(input,sizeof(input));
    if(!ok)pc_mirror_cipher_clear(c);
    return ok?PC_OK:PC_INVALID;
}
int pc_mirror_cipher_update(struct pc_mirror_cipher *c,const uint8_t *input,size_t n,uint8_t *out,size_t cap){
    if(!c || !c->context || !input || !out || n>1024U*1024 || cap<n || n>UINT64_MAX-c->bytes)return PC_INVALID;
    if(!n)return PC_OK;
    /* EVP permits exact in-place operation, but not partially overlapping
     * ranges. Reject that before advancing the counter or touching output. */
    uintptr_t from=(uintptr_t)input,to=(uintptr_t)out;
    if(from!=to && (from<to ? to-from<n : from-to<n))return PC_INVALID;
    int written=0;
    if(EVP_DecryptUpdate(c->context,out,&written,input,(int)n)!=1 || written!=(int)n){
        OPENSSL_cleanse(out,n);pc_mirror_cipher_clear(c);return PC_INVALID;
    }
    c->bytes+=n;return PC_OK;
}

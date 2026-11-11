/* Original PiCast SRP-6a server. Protocol: RFC5054 and documented AirPlay
 * legacy SHA1/40-byte K variant. OpenSSL supplies arithmetic and primitives.
 * SRP_get_default_gN is used only for the standard group's public constants. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "picast_srp.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/srp.h>
#include <string.h>
#include <stdlib.h>

struct private_srp {
    BIGNUM *n, *g, *v, *b;
    uint8_t salt[16], public_b[256], user_hash[20], shared[40];
};
static int digest(const EVP_MD *md, const void *p, size_t n, uint8_t *out) {
    unsigned count=0;
    return EVP_Digest(p,n,out,&count,md,NULL)==1 && count==(unsigned)EVP_MD_get_size(md);
}
void pc_srp_clear(struct pc_srp *s) {
    if (!s) return;
    struct private_srp *p=s->private_state;
    if (p) {
        BN_free(p->n); BN_free(p->g); BN_clear_free(p->v); BN_clear_free(p->b);
        OPENSSL_clear_free(p,sizeof(*p));
    }
    s->private_state=NULL; s->phase=0;
}
int pc_srp_start(struct pc_srp *s, const char *user, const char pin[5],
                 uint8_t salt[16], uint8_t public_b[256]) {
    if (!s || s->phase || s->private_state || !user || !pin || !salt || !public_b) return -1;
    size_t len=strnlen(user,65);
    if (!len || len>64 || pin[4]) return -1;
    for (size_t i=0;i<len;i++) if ((unsigned char)user[i]<0x21 || (unsigned char)user[i]>0x7e) return -1;
    for (size_t i=0;i<4;i++) if (pin[i]<'0' || pin[i]>'9') return -1;
    struct private_srp *p=OPENSSL_zalloc(sizeof(*p));
    if (!p) return -1;
    s->private_state=p;
    const SRP_gN *group=SRP_get_default_gN("2048");
    BN_CTX *ctx=BN_CTX_secure_new();
    BIGNUM *x=NULL,*k=NULL,*temp=BN_new(),*pub=BN_new();
    uint8_t buffer[512]={0}, hash[20], secret[32]; int ok=0;
    if (!group || !ctx || !temp || !pub) goto done;
    p->n=BN_dup(group->N); p->g=BN_dup(group->g); p->v=BN_secure_new(); p->b=BN_secure_new();
    if (!p->n || !p->g || !p->v || !p->b || BN_num_bits(p->n)!=2048 ||
        RAND_priv_bytes(secret,sizeof(secret))!=1 || RAND_bytes(p->salt,16)!=1) goto done;
    secret[0]|=0x80;
    if (!BN_bin2bn(secret,32,p->b)) goto done;
    BN_set_flags(p->b,BN_FLG_CONSTTIME);
    memcpy(buffer,user,len); buffer[len]=':'; memcpy(buffer+len+1,pin,4);
    if (!digest(EVP_sha1(),buffer,len+5,hash)) goto done;
    memcpy(buffer,p->salt,16); memcpy(buffer+16,hash,20);
    if (!digest(EVP_sha1(),buffer,36,hash) || !(x=BN_bin2bn(hash,20,NULL))) goto done;
    BN_set_flags(x,BN_FLG_CONSTTIME);
    if (!BN_mod_exp_mont_consttime(p->v,p->g,x,p->n,ctx,NULL)) goto done;
    if (BN_bn2binpad(p->n,buffer,256)!=256 || BN_bn2binpad(p->g,buffer+256,256)!=256 ||
        !digest(EVP_sha1(),buffer,512,hash) || !(k=BN_bin2bn(hash,20,NULL))) goto done;
    /* B = (k*v + g^b) mod N. */
    if (!BN_mod_exp_mont_consttime(temp,p->g,p->b,p->n,ctx,NULL) ||
        !BN_mod_mul(pub,k,p->v,p->n,ctx) || !BN_mod_add(pub,pub,temp,p->n,ctx) || BN_is_zero(pub) ||
        BN_bn2binpad(pub,p->public_b,256)!=256 || !digest(EVP_sha1(),user,len,p->user_hash)) goto done;
    memcpy(salt,p->salt,16); memcpy(public_b,p->public_b,256); s->phase=1; ok=1;
done:
    BN_clear_free(x); BN_free(k); BN_clear_free(temp); BN_free(pub); BN_CTX_free(ctx);
    OPENSSL_cleanse(buffer,sizeof(buffer)); OPENSSL_cleanse(hash,sizeof(hash)); OPENSSL_cleanse(secret,sizeof(secret));
    if (!ok) pc_srp_clear(s);
    return ok?0:-1;
}
int pc_srp_prove(struct pc_srp *s, const uint8_t a[256], const uint8_t proof[20], uint8_t m2[20]) {
    if (!s || s->phase!=1 || !s->private_state || !a || !proof || !m2) return -1;
    struct private_srp *p=s->private_state;
    BIGNUM *A=BN_bin2bn(a,256,NULL),*u=NULL,*shared=BN_secure_new(),*temp=BN_new();
    BN_CTX *ctx=BN_CTX_secure_new();
    uint8_t buffer[512]={0}, hash[20], expected[20], hn[20], hg[20]; int ok=0;
    if (!A || !shared || !temp || !ctx || BN_is_zero(A) || BN_cmp(A,p->n)>=0) goto done;
    memcpy(buffer,a,256); memcpy(buffer+256,p->public_b,256);
    if (!digest(EVP_sha1(),buffer,512,hash) || !(u=BN_bin2bn(hash,20,NULL)) || BN_is_zero(u)) goto done;
    /* S = (A*v^u)^b mod N. */
    if (!BN_mod_exp(temp,p->v,u,p->n,ctx) || !BN_mod_mul(temp,temp,A,p->n,ctx) ||
        !BN_mod_exp_mont_consttime(shared,temp,p->b,p->n,ctx,NULL) || BN_is_zero(shared)) goto done;
    /* SRP integer conversion is minimal big-endian; the four-byte counter
     * and doubled SHA1 digest are the legacy AirPlay variation. */
    int n=BN_num_bytes(shared);
    if (n<1 || n>256 || BN_bn2bin(shared,buffer)!=n) goto done;
    memset(buffer+n,0,4);
    if (!digest(EVP_sha1(),buffer,(size_t)n+4,p->shared)) goto done;
    buffer[n+3]=1;
    if (!digest(EVP_sha1(),buffer,(size_t)n+4,p->shared+20)) goto done;
    if (BN_bn2binpad(p->n,buffer,256)!=256 || !digest(EVP_sha1(),buffer,256,hn)) goto done;
    n=BN_bn2bin(p->g,buffer);
    if (n<1 || !digest(EVP_sha1(),buffer,(size_t)n,hg)) goto done;
    uint8_t transcript[612];
    for (size_t i=0;i<20;i++) transcript[i]=hn[i]^hg[i];
    memcpy(transcript+20,p->user_hash,20); memcpy(transcript+40,p->salt,16);
    memcpy(transcript+56,a,256); memcpy(transcript+312,p->public_b,256); memcpy(transcript+568,p->shared,40);
    if (!digest(EVP_sha1(),transcript,608,expected) || CRYPTO_memcmp(expected,proof,20)) {
        OPENSSL_cleanse(transcript,sizeof(transcript)); goto done;
    }
    memcpy(transcript,a,256); memcpy(transcript+256,proof,20); memcpy(transcript+276,p->shared,40);
    if (digest(EVP_sha1(),transcript,316,hash)) { memcpy(m2,hash,20); s->phase=2; ok=1; }
    OPENSSL_cleanse(transcript,sizeof(transcript));
done:
    BN_free(A); BN_free(u); BN_clear_free(shared); BN_clear_free(temp); BN_CTX_free(ctx);
    OPENSSL_cleanse(buffer,sizeof(buffer)); OPENSSL_cleanse(hash,sizeof(hash)); OPENSSL_cleanse(expected,sizeof(expected));
    if (!ok) pc_srp_clear(s);
    return ok?0:-1;
}
int pc_srp_keys(struct pc_srp *s, uint8_t key[16], uint8_t iv[16]) {
    if (!s || s->phase!=2 || !s->private_state || !key || !iv) return -1;
    struct private_srp *p=s->private_state;
    const char *labels[]={"Pair-Setup-AES-Key","Pair-Setup-AES-IV"};
    uint8_t results[2][64], buffer[64]; int ok=1;
    for (unsigned i=0;i<2;i++) {
        size_t n=strlen(labels[i]); memcpy(buffer,labels[i],n); memcpy(buffer+n,p->shared,40);
        if (!digest(EVP_sha512(),buffer,n+40,results[i])) ok=0;
    }
    if (ok) { memcpy(key,results[0],16); memcpy(iv,results[1],16); }
    OPENSSL_cleanse(results,sizeof(results)); OPENSSL_cleanse(buffer,sizeof(buffer)); pc_srp_clear(s);
    return ok?0:-1;
}

#include "picast_pair.h"
#include <openssl/crypto.h>
#include <string.h>

static int public_key(EVP_PKEY *key, uint8_t out[32]) {
    size_t n=32;
    return key && EVP_PKEY_get_raw_public_key(key,out,&n)==1 && n==32;
}
int pc_identity_public(const uint8_t seed[32], uint8_t out[32]) {
    if (!seed || !out) return -1;
    EVP_PKEY *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,32);
    uint8_t result[32]; int ok=public_key(key,result);
    EVP_PKEY_free(key);
    if (ok) memcpy(out,result,32);
    return ok ? 0 : -1;
}
void pc_pair_clear(struct pc_pair_verify *p) {
    if (!p) return;
    EVP_CIPHER_CTX_free(p->cipher); EVP_PKEY_free(p->identity);
    OPENSSL_cleanse(p,sizeof(*p)); p->phase=PC_PAIR_FAILED;
}
static int fail(struct pc_pair_verify *p) {
    if (p) {
        EVP_CIPHER_CTX_free(p->cipher); p->cipher=NULL;
        OPENSSL_cleanse(p->shared_secret,32);
        OPENSSL_cleanse(p->client_x,32); OPENSSL_cleanse(p->server_x,32);
        p->phase=PC_PAIR_FAILED;
    }
    return -1;
}
int pc_pair_init(struct pc_pair_verify *p, const uint8_t seed[32], const uint8_t client[32]) {
    if (!p || !seed || !client) return -1;
    memset(p,0,sizeof(*p));
    p->identity=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,32);
    if (!p->identity) return fail(p);
    memcpy(p->trusted_client,client,32); p->phase=PC_PAIR_READY;
    return 0;
}
static int labeled_hash(const char *label, const uint8_t secret[32], uint8_t out[16]) {
    uint8_t hash[64]; unsigned size=0;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    int ok=ctx && EVP_DigestInit_ex(ctx,EVP_sha512(),NULL)==1 &&
        EVP_DigestUpdate(ctx,label,strlen(label))==1 && EVP_DigestUpdate(ctx,secret,32)==1 &&
        EVP_DigestFinal_ex(ctx,hash,&size)==1 && size==64;
    if (ok) memcpy(out,hash,16);
    OPENSSL_cleanse(hash,sizeof(hash)); EVP_MD_CTX_free(ctx); return ok;
}
int pc_pair_begin(struct pc_pair_verify *p, const uint8_t *request, size_t n, uint8_t response[96]) {
    if (!p || p->phase!=PC_PAIR_READY || !p->identity || !request || !response || n!=68 ||
        memcmp(request,"\1\0\0\0",4) || CRYPTO_memcmp(request+36,p->trusted_client,32)) return fail(p);
    int ok=0, count=0; size_t shared_n=32, signature_n=64;
    uint8_t shared[32]={0}, key[16]={0}, iv[16]={0}, signed_message[64], signature[64]={0}, result[96];
    EVP_PKEY_CTX *generation=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL), *derive=NULL;
    EVP_PKEY *ephemeral=NULL, *remote=NULL;
    EVP_MD_CTX *sign=EVP_MD_CTX_new();
    if (!generation || EVP_PKEY_keygen_init(generation)!=1 || EVP_PKEY_keygen(generation,&ephemeral)!=1 ||
        !public_key(ephemeral,p->server_x)) goto done;
    remote=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,request+4,32);
    derive=EVP_PKEY_CTX_new(ephemeral,NULL);
    if (!remote || !derive || EVP_PKEY_derive_init(derive)!=1 || EVP_PKEY_derive_set_peer(derive,remote)!=1 ||
        EVP_PKEY_derive(derive,shared,&shared_n)!=1 || shared_n!=32 ||
        !labeled_hash("Pair-Verify-AES-Key",shared,key) || !labeled_hash("Pair-Verify-AES-IV",shared,iv)) goto done;
    memcpy(p->client_x,request+4,32); memcpy(signed_message,p->server_x,32); memcpy(signed_message+32,p->client_x,32);
    if (!sign || EVP_DigestSignInit(sign,NULL,NULL,NULL,p->identity)!=1 ||
        EVP_DigestSign(sign,signature,&signature_n,signed_message,64)!=1 || signature_n!=64) goto done;
    p->cipher=EVP_CIPHER_CTX_new();
    memcpy(result,p->server_x,32);
    if (!p->cipher || EVP_EncryptInit_ex(p->cipher,EVP_aes_128_ctr(),NULL,key,iv)!=1 ||
        EVP_EncryptUpdate(p->cipher,result+32,&count,signature,64)!=1 || count!=64) goto done;
    memcpy(p->shared_secret,shared,32);
    memcpy(response,result,96); p->phase=PC_PAIR_WAITING; ok=1;
done:
    EVP_MD_CTX_free(sign); EVP_PKEY_CTX_free(derive); EVP_PKEY_CTX_free(generation);
    EVP_PKEY_free(ephemeral); EVP_PKEY_free(remote);
    OPENSSL_cleanse(shared,sizeof(shared)); OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(iv,sizeof(iv));
    OPENSSL_cleanse(signature,sizeof(signature)); OPENSSL_cleanse(result,sizeof(result));
    return ok ? 0 : fail(p);
}
int pc_pair_finish(struct pc_pair_verify *p, const uint8_t *request, size_t n) {
    if (!p || p->phase!=PC_PAIR_WAITING || !p->cipher || !request || n!=68 || memcmp(request,"\0\0\0\0",4)) return fail(p);
    uint8_t signature[64]={0}, message[64]; int count=0;
    EVP_PKEY *client=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,p->trusted_client,32);
    EVP_MD_CTX *verify=EVP_MD_CTX_new();
    memcpy(message,p->client_x,32); memcpy(message+32,p->server_x,32);
    /* Continue the CTR stream after the 64-byte server signature. Restarting
     * at the original IV would verify the wrong client proof. */
    int ok=client && verify && EVP_EncryptUpdate(p->cipher,signature,&count,request+4,64)==1 && count==64 &&
        EVP_DigestVerifyInit(verify,NULL,NULL,NULL,client)==1 && EVP_DigestVerify(verify,signature,64,message,64)==1;
    EVP_MD_CTX_free(verify); EVP_PKEY_free(client); OPENSSL_cleanse(signature,sizeof(signature));
    if (!ok) return fail(p);
    EVP_CIPHER_CTX_free(p->cipher); p->cipher=NULL; p->phase=PC_PAIR_VERIFIED;
    return 0;
}

int pc_pair_media_secret(const struct pc_pair_verify *p,uint8_t out[32]) {
    if (!p || !out || p->phase!=PC_PAIR_VERIFIED) return -1;
    memcpy(out,p->shared_secret,32); return 0;
}

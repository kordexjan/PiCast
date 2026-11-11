#include <stdlib.h>
#include <unistd.h>
#include "picast_pair.h"
#include "picast_control.h"
#include "picast_info.h"
#include <assert.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

/* Separate client implementation using EVP directly, never the server's
 * derivation/signature helpers. Synthetic protocol tests, no Apple client. */
static EVP_PKEY *key(int type, const uint8_t seed[32], uint8_t pub[32]) {
    EVP_PKEY *k=EVP_PKEY_new_raw_private_key(type,NULL,seed,32);
    size_t n=32;
    assert(k && EVP_PKEY_get_raw_public_key(k,pub,&n)==1 && n==32);
    return k;
}
static void fromhex(const char *s, uint8_t *out, size_t n) {
    assert(strlen(s)==2*n);
    for (size_t i=0;i<n;i++) {
        unsigned value;
        assert(sscanf(s+2*i,"%2x",&value)==1); out[i]=(uint8_t)value;
    }
}
static void identity_vector(void) {
    /* RFC 8032 section 7.1 TEST 1. */
    uint8_t seed[32], expected[32], pub[32], signature[64];
    fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",seed,32);
    fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",expected,32);
    fromhex("e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b",signature,64);
    assert(pc_identity_public(seed,pub)==0 && !memcmp(pub,expected,32));
    EVP_PKEY *k=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,pub,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); assert(ctx && k);
    assert(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,k)==1);
    assert(EVP_DigestVerify(ctx,signature,64,(const uint8_t *)"",0)==1);
    signature[0]^=1;
    assert(EVP_DigestVerify(ctx,signature,64,(const uint8_t *)"",0)==0);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(k);
}
static void derive(EVP_PKEY *own, const uint8_t remote[32], uint8_t out[32]) {
    EVP_PKEY *peer=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,remote,32);
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(own,NULL); size_t n=32;
    assert(peer && ctx && EVP_PKEY_derive_init(ctx)==1 && EVP_PKEY_derive_set_peer(ctx,peer)==1);
    assert(EVP_PKEY_derive(ctx,out,&n)==1 && n==32);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
}
static void hash(const char *label, const uint8_t shared[32], uint8_t out[16]) {
    /* Deliberately one-shot digest of concatenated input. */
    uint8_t input[64], digest[64]; unsigned n=0; size_t len=strlen(label);
    assert(len+32<=sizeof(input)); memcpy(input,label,len); memcpy(input+len,shared,32);
    assert(EVP_Digest(input,len+32,digest,&n,EVP_sha512(),NULL)==1 && n==64);
    memcpy(out,digest,16); OPENSSL_cleanse(input,sizeof(input)); OPENSSL_cleanse(digest,sizeof(digest));
}
static void client_proof(EVP_PKEY *x, EVP_PKEY *ed, const uint8_t server_pub[32],
                         const uint8_t begin[68], const uint8_t response[96], uint8_t proof[68], int restart) {
    uint8_t shared[32], aes[16], iv[16], signature[64], message[64]; int n=0;
    derive(x,response,shared); hash("Pair-Verify-AES-Key",shared,aes); hash("Pair-Verify-AES-IV",shared,iv);
    EVP_CIPHER_CTX *cipher=EVP_CIPHER_CTX_new();
    assert(cipher && EVP_EncryptInit_ex(cipher,EVP_aes_128_ctr(),NULL,aes,iv)==1);
    assert(EVP_EncryptUpdate(cipher,signature,&n,response+32,64)==1 && n==64);
    memcpy(message,response,32); memcpy(message+32,begin+4,32);
    EVP_PKEY *server=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,server_pub,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); assert(ctx && server);
    assert(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,server)==1);
    assert(EVP_DigestVerify(ctx,signature,64,message,64)==1);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(server);
    memcpy(message,begin+4,32); memcpy(message+32,response,32);
    ctx=EVP_MD_CTX_new(); size_t size=64;
    assert(ctx && EVP_DigestSignInit(ctx,NULL,NULL,NULL,ed)==1);
    assert(EVP_DigestSign(ctx,signature,&size,message,64)==1 && size==64);
    EVP_MD_CTX_free(ctx);
    if (restart) assert(EVP_EncryptInit_ex(cipher,EVP_aes_128_ctr(),NULL,aes,iv)==1);
    memset(proof,0,4); assert(EVP_EncryptUpdate(cipher,proof+4,&n,signature,64)==1 && n==64);
    EVP_CIPHER_CTX_free(cipher);
    OPENSSL_cleanse(shared,sizeof(shared)); OPENSSL_cleanse(aes,sizeof(aes));
    OPENSSL_cleanse(iv,sizeof(iv)); OPENSSL_cleanse(signature,sizeof(signature));
}
static void exchanges(void) {
    uint8_t server_seed[32]={1}, client_seed[32]={2}, x_seed[32]={3};
    uint8_t server_pub[32], client_pub[32], begin[68]={1}, response[96], proof[68];
    assert(pc_identity_public(server_seed,server_pub)==0);
    EVP_PKEY *ed=key(EVP_PKEY_ED25519,client_seed,client_pub);
    EVP_PKEY *x=key(EVP_PKEY_X25519,x_seed,begin+4); memcpy(begin+36,client_pub,32);
    for (int mode=0;mode<5;mode++) {
        struct pc_pair_verify p;
        assert(pc_pair_init(&p,server_seed,client_pub)==0);
        assert(pc_pair_begin(&p,begin,68,response)==0 && p.phase==PC_PAIR_WAITING);
        uint8_t secret[32],expected_secret[32];memset(secret,0xa5,32);
        assert(pc_pair_media_secret(&p,secret)==-1 && secret[0]==0xa5);
        derive(x,response,expected_secret);
        client_proof(x,ed,server_pub,begin,response,proof,mode==2);
        if (mode==1) proof[19]^=1;
        if (mode==3) proof[1]=1;
        int result=pc_pair_finish(&p,proof,mode==4 ? 67 : 68);
        assert(mode==0 ? result==0 && p.phase==PC_PAIR_VERIFIED : result==-1 && p.phase==PC_PAIR_FAILED);
        if(!mode){assert(pc_pair_media_secret(&p,secret)==0 && !CRYPTO_memcmp(secret,expected_secret,32));}
        else {assert(pc_pair_media_secret(&p,secret)==-1);assert(!memcmp(p.shared_secret,(uint8_t[32]){0},32));}
        assert(pc_pair_finish(&p,proof,68)==-1); /* replay fails closed */
        assert(!memcmp(p.shared_secret,(uint8_t[32]){0},32));
        pc_pair_clear(&p); pc_pair_clear(&p); /* idempotent release */
    }
    for (int mode=0;mode<5;mode++) {
        struct pc_pair_verify p; uint8_t bad[68], saved[96];
        memcpy(bad,begin,68); memset(response,0xa7,96); memcpy(saved,response,96);
        if (mode==0) bad[36]^=1;  /* unauthorized identity */
        if (mode==1) memset(bad+4,0,32); /* low-order DH input */
        if (mode==2) bad[3]=1;
        assert(pc_pair_init(&p,server_seed,client_pub)==0);
        if (mode==4) assert(pc_pair_finish(&p,bad,68)==-1);
        assert(pc_pair_begin(&p,bad,mode==3 ? 67 : 68,response)==-1 && p.phase==PC_PAIR_FAILED);
        assert(!memcmp(response,saved,96)); pc_pair_clear(&p);
    }
    EVP_PKEY_free(ed); EVP_PKEY_free(x);
}
static size_t control_request(struct pc_control *c, const char *method, const char *target,
                              unsigned seq, const uint8_t *body, size_t body_n, unsigned status,
                              uint8_t result[96]) {
    uint8_t request[512], response[512];
    int h=snprintf((char *)request,sizeof(request),"%s %s RTSP/1.0\r\nCSeq: %u\r\nContent-Length: %zu\r\n\r\n",method,target,seq,body_n);
    assert(h>0 && (size_t)h+body_n<sizeof(request));
    if (body_n) memcpy(request+h,body,body_n);
    size_t len=(size_t)h+body_n, written=777, consumed=777;
    struct pc_control before=*c;
    for (size_t i=0;i<len;i++) {
        memset(response,0xa7,sizeof(response));
        assert(pc_control_request(c,request,i,response,sizeof(response),&written,&consumed)==PC_OTHER);
        assert(!written && !consumed && !memcmp(c,&before,sizeof(before)));
        for (size_t j=0;j<sizeof(response);j++) assert(response[j]==0xa7);
    }
    assert(pc_control_request(c,request,len,response,511,&written,&consumed)==PC_INVALID);
    assert(!memcmp(c,&before,sizeof(before)));
    /* Bytes after the first framed request must remain unconsumed. */
    memcpy(request+len,"NEXT",4);
    assert(pc_control_request(c,request,len+4,response,sizeof(response),&written,&consumed)==PC_OK && consumed==len);
    assert(written<sizeof(response)); response[written]=0;
    unsigned actual=0; assert(sscanf((char *)response,"RTSP/1.0 %u",&actual)==1 && actual==status);
    char cseq[40]; snprintf(cseq,sizeof(cseq),"\r\nCSeq: %u\r\n",seq);
    assert(strstr((char *)response,cseq));
    uint8_t *end=(uint8_t *)strstr((char *)response,"\r\n\r\n"); assert(end);
    size_t size=written-(size_t)(end+4-response); assert(size<=200);
    if (size) memcpy(result,end+4,size);
    return size;
}
static void control_exchange(void) {
    uint8_t seed[32]={11}, ed_seed[32]={22}, x_seed[32]={33};
    uint8_t client_pub[32], server_pub[96], begin[68]={1}, reply[96], proof[68];
    EVP_PKEY *ed=key(EVP_PKEY_ED25519,ed_seed,client_pub);
    EVP_PKEY *x=key(EVP_PKEY_X25519,x_seed,begin+4); memcpy(begin+36,client_pub,32);
    struct pc_control c;
    assert(pc_control_init(&c,seed,1)==PC_OK);
    assert(control_request(&c,"OPTIONS","*",0,NULL,0,200,reply)==0);
    /* Classification probes must not turn unsupported FairPlay into success. */
    const uint8_t fp_start[16]={'F','P','L','Y',3};
    const uint8_t fp_next[164]={'F','P','L','Y',3};
    assert(control_request(&c,"POST","/fp-setup",0,fp_start,sizeof(fp_start),501,reply)==0);
    assert(c.phase==PC_CONTROL_NEW);
    assert(control_request(&c,"POST","/fp-setup",0,fp_next,sizeof(fp_next),501,reply)==0);
    assert(c.phase==PC_CONTROL_NEW);
    assert(control_request(&c,"POST","/pair-setup",1,client_pub,32,200,server_pub)==32);
    assert(c.phase==PC_CONTROL_PAIRED);
    assert(control_request(&c,"POST","/pair-verify",2,begin,68,200,reply)==96);
    client_proof(x,ed,server_pub,begin,reply,proof,0);
    assert(control_request(&c,"POST","/pair-verify",3,proof,68,200,reply)==0 && c.phase==PC_CONTROL_VERIFIED);
    uint8_t fp_request[16]={'F','P','L','Y',3,1,1,0,0,0,0,4,2,0,3,0};
    uint8_t fp_reply[200],fp_message[164]={0};
    assert(control_request(&c,"POST","/fp-setup",4,fp_request,16,200,fp_reply)==142);
    memcpy(fp_message,"FPLY\x03\x01\x03",7);fp_message[11]=152;
    assert(control_request(&c,"POST","/fp-setup",5,fp_message,164,200,fp_reply)==32);
    assert(c.phase==PC_CONTROL_VERIFIED && c.fairplay.phase==2);
    assert(control_request(&c,"POST","/pair-verify",5,proof,68,401,reply)==0 && c.phase==PC_CONTROL_CLOSED);
    /* A later session: same identity from disk, sender only verifies. */
    char dir[]="/tmp/picast-pairing-XXXXXX"; assert(mkdtemp(dir));
    uint8_t stored[32],again[32];
    assert(!pc_pairing_identity(dir,stored) && !pc_pairing_identity(dir,again) && !memcmp(stored,again,32));
    assert(!pc_pairing_known(dir,client_pub) && !pc_pairing_known(NULL,client_pub));
    struct pc_control later;
    assert(pc_control_init(&later,stored,0)==PC_OK); later.state_dir=dir;
    assert(control_request(&later,"POST","/pair-verify",6,begin,68,401,reply)==0 && later.phase==PC_CONTROL_CLOSED);
    assert(!pc_pairing_remember(dir,client_pub) && !pc_pairing_remember(dir,client_pub) && pc_pairing_known(dir,client_pub));
    char keys[600]; snprintf(keys,sizeof(keys),"%s/paired.keys",dir);
    FILE *file=fopen(keys,"rb"); assert(file); assert(!fseek(file,0,SEEK_END) && ftell(file)==32); fclose(file);
    pc_control_clear(&later);
    assert(pc_control_init(&later,stored,0)==PC_OK); later.state_dir=dir;
    uint8_t later_public[96];
    assert(control_request(&later,"POST","/pair-verify",6,begin,68,200,later_public)==96 && later.phase==PC_CONTROL_PAIRED);
    client_proof(x,ed,later.identity_public,begin,later_public,proof,0);
    assert(control_request(&later,"POST","/pair-verify",7,proof,68,200,reply)==0 && later.phase==PC_CONTROL_VERIFIED);
    pc_control_clear(&later);
    char identity[600]; snprintf(identity,sizeof(identity),"%s/identity.key",dir);
    assert(!remove(keys) && !remove(identity) && !rmdir(dir));
    pc_control_clear(&c);
    assert(pc_control_init(&c,seed,0)==PC_OK);
    assert(control_request(&c,"POST","/pair-setup",1,client_pub,32,401,reply)==0 && c.phase==PC_CONTROL_CLOSED);
    pc_control_clear(&c);
    assert(pc_control_init(&c,seed,1)==PC_OK);
    assert(control_request(&c,"POST","/pair-setup",1,client_pub,31,400,reply)==0 && c.phase==PC_CONTROL_CLOSED);
    pc_control_clear(&c);
    assert(pc_control_init(&c,seed,1)==PC_OK);
    assert(control_request(&c,"POST","/pair-verify",1,begin,68,401,reply)==0 && c.phase==PC_CONTROL_CLOSED);
    pc_control_clear(&c); pc_control_clear(&c);
    EVP_PKEY_free(ed); EVP_PKEY_free(x);
}
static void info_test(int vector) {
    uint8_t seed[32]={11}, response[2048], id[6]={2,1,2,3,4,5};
    const uint8_t request[]="GET /info RTSP/1.0\r\nCSeq: 7\r\n\r\n";
    struct pc_control c; size_t written=0, consumed=0;
    assert(pc_control_init(&c,seed,1)==PC_OK); memcpy(c.device_id,id,6);
    assert(pc_control_request(&c,request,sizeof(request)-1,response,sizeof(response),&written,&consumed)==PC_OK);
    assert(c.phase==PC_CONTROL_NEW && consumed==sizeof(request)-1 && written<sizeof(response));
    response[written]=0;
    assert(!memcmp(response,"RTSP/1.0 200 OK\r\n",17));
    assert(strstr((char *)response,"Content-Type: application/x-apple-binary-plist\r\n"));
    uint8_t *body=(uint8_t *)strstr((char *)response,"\r\n\r\n"); assert(body); body+=4;
    size_t n=written-(size_t)(body-response); assert(n>8 && !memcmp(body,"bplist00",8));
    if (vector) assert(fwrite(body,1,n,stdout)==n);
    memset(response,0xa7,sizeof(response));
    assert(pc_info_encode(id,c.identity_public,response,7,&written)==PC_INVALID && !written);
    for (size_t i=0;i<sizeof(response);i++) assert(response[i]==0xa7);
    id[0]=3;
    assert(pc_info_encode(id,c.identity_public,response,sizeof(response),&written)==PC_INVALID && !written);
    pc_control_clear(&c);
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--info-vector")) { info_test(1); return 0; }
    assert(argc==1);
    info_test(0);
    identity_vector(); exchanges(); control_exchange();
    puts("pair-verify: RFC identity vector, independent client, tampering, CTR continuity, replay, state, info and fragmented RTSP session checks passed (synthetic; no Apple interoperability claim)");
    return 0;
}

/* Original bounded legacy PIN protocol. No imported receiver implementation. */
#include "picast_pin.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <plist/plist.h>
typedef plist_t dictionary;
static dictionary decode(const uint8_t *data,size_t n){plist_t d=NULL;if(plist_from_bin((const char *)data,(uint32_t)n,&d)!=PLIST_ERR_SUCCESS)return NULL;if(plist_get_node_type(d)!=PLIST_DICT){plist_free(d);return NULL;}return d;}
static void release(dictionary d){if(d)plist_free(d);}
static size_t count(dictionary d){return plist_dict_get_size(d);}
static int field(dictionary d,const char *name,int string,uint8_t *out,size_t n){
    plist_t v=plist_dict_get_item(d,name);if(!v)return 0;uint64_t len=0;
    if(string){if(plist_get_node_type(v)!=PLIST_STRING)return 0;const char *p=plist_get_string_ptr(v,&len);if(!p || len>=n || memchr(p,0,(size_t)len))return 0;memcpy(out,p,(size_t)len);out[len]=0;return 1;}
    if(plist_get_node_type(v)!=PLIST_DATA)return 0;
    const char *p=plist_get_data_ptr(v,&len);if(!p || len!=n)return 0;memcpy(out,p,n);return 1;
}
static int encode(const char *a,const uint8_t *av,size_t an,const char *b,const uint8_t *bv,size_t bn,uint8_t *out,size_t cap,size_t *written){
    plist_t d=plist_new_dict(),x=plist_new_data((const char *)av,an),y=b?plist_new_data((const char *)bv,bn):NULL;char *raw=NULL;uint32_t n=0;int ok=0;
    if(!d || !x || (b && !y)){if(x)plist_free(x);if(y)plist_free(y);goto done;}
    plist_dict_set_item(d,a,x);if(b)plist_dict_set_item(d,b,y);
    if(plist_dict_get_size(d)==(b?2U:1U) && plist_to_bin(d,&raw,&n)==PLIST_ERR_SUCCESS && raw && n<=cap){memcpy(out,raw,n);*written=n;ok=1;}
done:
    if(d)plist_free(d);
    if(raw)plist_mem_free(raw);
    return ok;
}
void pc_pin_clear(struct pc_pin *p){if(!p)return;pc_srp_clear(&p->srp);OPENSSL_cleanse(p,sizeof(*p));}
int pc_pin_begin(struct pc_pin *p){
    if(!p || p->phase)return -1;
    uint32_t random=0;
    do {if(RAND_priv_bytes((uint8_t *)&random,sizeof(random))!=1)return -1;}while(random>=UINT32_C(4294960000));
    snprintf(p->code,sizeof(p->code),"%04u",(unsigned)(random%10000));
    memcpy(p->retry_code,p->code,sizeof(p->code));p->wrong_attempts=0;p->phase=1;return 0;
}
static int gcm(int encrypt,const uint8_t key[16],const uint8_t iv[16],const uint8_t in[32],uint8_t out[32],uint8_t tag[16]){
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();uint8_t buffer[48];int n=0,last=0,ok=0;
    if(!c)goto done;
    if(EVP_CipherInit_ex(c,EVP_aes_128_gcm(),NULL,NULL,NULL,encrypt)!=1 || EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,16,NULL)!=1 || EVP_CipherInit_ex(c,NULL,NULL,key,iv,encrypt)!=1)goto done;
    if(!encrypt && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,tag)!=1)goto done;
    if(EVP_CipherUpdate(c,buffer,&n,in,32)!=1 || n!=32 || EVP_CipherFinal_ex(c,buffer+n,&last)!=1 || last!=0)goto done;
    if(encrypt && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)!=1)goto done;
    memcpy(out,buffer,32);ok=1;
done:
    OPENSSL_cleanse(buffer,sizeof(buffer));EVP_CIPHER_CTX_free(c);return ok;
}
int pc_pin_request(struct pc_pin *p,const uint8_t *input,size_t n,const uint8_t own[32],uint8_t *out,size_t cap,size_t *written){
    if(!written)return -1;
    *written=0;
    if(!p || !p->phase || p->phase>3 || !input || n<8 || n>1024 || memcmp(input,"bplist00",8) || !own || !out || cap<512)return -1;
    dictionary d=decode(input,n);int ok=0;
    uint8_t a[256],proof[20],salt[16],pub[256],peer[32],tag[16];
    if(!d || count(d)!=2)goto done;
    /* The sender started over after a lost reply; that is no wrong guess. */
    char restarted[8]={0};
    if(p->phase==2 && field(d,"method",1,(uint8_t *)restarted,sizeof(restarted))){
        pc_srp_clear(&p->srp);memcpy(p->code,p->retry_code,sizeof(p->code));p->phase=1;
    }
    if(p->phase==1){
        char method[8]={0},user[18]={0};
        if(!field(d,"method",1,(uint8_t *)method,sizeof(method)) || strcmp(method,"pin") || !field(d,"user",1,(uint8_t *)user,sizeof(user)) || strlen(user)!=17)goto done;
        for(unsigned i=0;i<17;i++)if(i%3==2 ? user[i]!=':' : !((user[i]>='0' && user[i]<='9') || (user[i]>='A' && user[i]<='F') || (user[i]>='a' && user[i]<='f')))goto done;
        if(pc_srp_start(&p->srp,user,p->code,salt,pub) || !encode("pk",pub,256,"salt",salt,16,out,cap,written))goto done;
        OPENSSL_cleanse(p->code,sizeof(p->code));p->phase=2;ok=1;
    }else if(p->phase==2){
        if(!field(d,"pk",0,a,256) || !field(d,"proof",0,proof,20) || pc_srp_prove(&p->srp,a,proof,proof) || !encode("proof",proof,20,NULL,NULL,0,out,cap,written) || pc_srp_keys(&p->srp,p->key,p->iv))goto done;
        OPENSSL_cleanse(p->retry_code,sizeof(p->retry_code));p->phase=3;ok=1;
    }else{
        if(!field(d,"epk",0,peer,32) || !field(d,"authTag",0,tag,16))goto done;
        p->iv[15]++;
        if(!gcm(0,p->key,p->iv,peer,p->peer_key,tag))goto done;
        p->iv[15]++;
        if(!gcm(1,p->key,p->iv,own,peer,tag) || !encode("epk",peer,32,"authTag",tag,16,out,cap,written))goto done;
        OPENSSL_cleanse(p->key,16);OPENSSL_cleanse(p->iv,16);p->phase=4;ok=1;
    }
done:
    release(d);OPENSSL_cleanse(a,sizeof(a));OPENSSL_cleanse(proof,sizeof(proof));OPENSSL_cleanse(peer,sizeof(peer));OPENSSL_cleanse(tag,sizeof(tag));
    if(!ok){
        /* iOS keeps its dialog open after a wrong code and asks again without a
         * new pair-pin-start, so the displayed code stays valid for a retry. */
        char code[5];unsigned wrong=p->wrong_attempts+1;int retry=(p->phase==1 || p->phase==2) && wrong<PC_PIN_MAX_ATTEMPTS;
        memcpy(code,p->retry_code,sizeof(code));
        pc_pin_clear(p);*written=0;
        if(retry){memcpy(p->code,code,sizeof(code));memcpy(p->retry_code,code,sizeof(code));p->wrong_attempts=wrong;p->phase=1;}
        OPENSSL_cleanse(code,sizeof(code));
    }
    return ok?0:-1;
}

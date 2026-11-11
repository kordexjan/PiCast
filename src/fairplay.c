#include "picast_fairplay.h"
#include "picast.h"
#include <openssl/crypto.h>
#include <string.h>
#include "picast_fairplay_data.h"
void pc_fairplay_clear(struct pc_fairplay *s){if(s)OPENSSL_cleanse(s,sizeof(*s));}
int pc_fairplay_wire(struct pc_fairplay *s,const uint8_t *in,size_t n,uint8_t *out,size_t cap,size_t *written){
    if(!written)return PC_INVALID;
    *written=0;
    if(!s || !in || !out || (n!=16 && n!=164))return PC_INVALID;
    if(memcmp(in,"FPLY",4) || in[4]!=3 || in[5]!=1 || in[7] || in[8] || in[9] || in[10])return PC_UNSUPPORTED;
    if(!s->phase && n==16 && in[6]==1 && in[11]==4 && in[12]==2 && !in[13]){
        if(in[14]>3)return PC_UNSUPPORTED;
        if(cap<sizeof(challenges[0]))return PC_INVALID;
        memcpy(out,challenges[in[14]],sizeof(challenges[0]));*written=sizeof(challenges[0]);s->phase=1;return PC_OK;
    }
    if(s->phase==1 && n==164 && in[6]==3 && in[11]==152){
        if(cap<32)return PC_INVALID;
        const uint8_t header[12]={'F','P','L','Y',3,1,4,0,0,0,0,20};
        memcpy(s->key_message,in,164);memcpy(out,header,12);memcpy(out+12,in+144,20);
        *written=32;s->phase=2;return PC_OK;
    }
    return PC_UNSUPPORTED;
}

#include "picast_control.h"
#include "picast_info.h"
#include "picast_media.h"
#include "picast_session.h"
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

static int equal(struct pc_span s, const char *text) {
    return s.size==strlen(text) && !memcmp(s.data,text,s.size);
}
int pc_control_init(struct pc_control *c, const uint8_t seed[32], int transient) {
    if (!c || !seed || (transient!=0 && transient!=1)) return PC_INVALID;
    memset(c,0,sizeof(*c)); c->pair.phase=PC_PAIR_FAILED;
    if (pc_identity_public(seed,c->identity_public)) { c->phase=PC_CONTROL_CLOSED; return PC_INVALID; }
    memcpy(c->identity_seed,seed,32); c->allow_transient=(unsigned)transient;
    memcpy(c->device_id,c->identity_public,6); c->device_id[0]=(c->device_id[0]&0xfc)|2;
    c->phase=PC_CONTROL_NEW; return PC_OK;
}
void pc_control_clear(struct pc_control *c) {
    if (!c) return;
    pc_pair_clear(&c->pair);
    pc_pin_clear(&c->pin);
    pc_fairplay_clear(&c->fairplay);
    OPENSSL_cleanse(c,sizeof(*c));
    c->phase=PC_CONTROL_CLOSED; c->pair.phase=PC_PAIR_FAILED;
}
#define PAIRING_MAX_PEERS 64U
static int pairing_path(const char *dir, const char *name, char *path, size_t n) {
    int written=dir ? snprintf(path,n,"%s/%s",dir,name) : -1;
    return written>0 && (size_t)written<n ? 0 : -1;
}
int pc_pairing_identity(const char *dir, uint8_t seed[32]) {
    char path[512];
    if (!seed || pairing_path(dir,"identity.key",path,sizeof(path))) return -1;
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd>=0) {
        ssize_t got=read(fd,seed,32); close(fd);
        if (got==32) return 0;
        unlink(path);  /* cut short by a power loss while first written */
    }
    /* Written to a new name, flushed, then renamed: a power cut never leaves a
     * half key, which would ask every device for the PIN again. */
    char fresh[520];
    if (snprintf(fresh,sizeof(fresh),"%s.new",path)>=(int)sizeof(fresh) || RAND_bytes(seed,32)!=1) return -1;
    fd=open(fresh,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
    if (fd<0) return -1;
    ssize_t put=write(fd,seed,32);
    int synced=fsync(fd)==0; close(fd);
    if (put!=32 || !synced || rename(fresh,path)) { unlink(fresh); return -1; }
    return 0;
}
int pc_pairing_known(const char *dir, const uint8_t key[32]) {
    char path[512]; uint8_t entry[32]; int known=0;
    if (!key || pairing_path(dir,"paired.keys",path,sizeof(path))) return 0;
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) return 0;
    for (unsigned i=0;i<PAIRING_MAX_PEERS && read(fd,entry,32)==32;i++)
        if (!CRYPTO_memcmp(entry,key,32)) known=1;
    close(fd);
    return known;
}
int pc_pairing_remember(const char *dir, const uint8_t key[32]) {
    char path[512];
    if (!key || pairing_path(dir,"paired.keys",path,sizeof(path))) return -1;
    if (pc_pairing_known(dir,key)) return 0;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);
    if (fd<0) return -1;
    off_t size=lseek(fd,0,SEEK_END);
    /* A record cut short by a power loss is dropped, so later ones stay aligned. */
    if (size>0 && size%32 && ftruncate(fd,size-size%32)==0) size-=size%32;
    ssize_t put=size>=0 && (size_t)size<PAIRING_MAX_PEERS*32U && size%32==0 ? write(fd,key,32) : -1;
    if (put==32 && fsync(fd)) put=-1;
    close(fd);
    return put==32 ? 0 : -1;
}
int pc_control_reconnect(struct pc_control *c) {
    if (!c) return PC_INVALID;
    pc_pair_clear(&c->pair); pc_fairplay_clear(&c->fairplay); c->phase=PC_CONTROL_NEW;
    if (c->pin.phase==4) {
        if (pc_pair_init(&c->pair,c->identity_seed,c->pin.peer_key)) {
            pc_control_clear(c); return PC_INVALID;
        }
        c->phase=PC_CONTROL_PAIRED;
    } else if (c->pin.phase!=1) pc_pin_clear(&c->pin);
    return PC_OK;
}
static int show_fresh_pin(struct pc_control *c) {
    if (!pc_pin_begin(&c->pin) && !c->show_pin(c->pin.code)) return 0;
    pc_pin_clear(&c->pin);
    return -1;
}

int pc_control_request(struct pc_control *c, const uint8_t *input, size_t n,
                       uint8_t *response, size_t capacity, size_t *written, size_t *consumed) {
    if (!written || !consumed) return PC_INVALID;
    *written=*consumed=0;
    if (!c || !response || capacity<512 || c->phase==PC_CONTROL_CLOSED) return PC_INVALID;
    struct pc_rtsp_request r;
    int parsed=pc_rtsp_parse(input,n,&r);
    if (parsed!=PC_OK) {
        if (parsed!=PC_OTHER) { pc_pair_clear(&c->pair); c->phase=PC_CONTROL_CLOSED; }
        return parsed;
    }
    unsigned status=501; uint8_t body[
4096
]; size_t size=0;
    const char *type=NULL; int pin_retry=0;
    if (equal(r.method,"OPTIONS") && !r.body.size) status=200;
    else if (equal(r.method,"GET") && equal(r.target,"/info")) {
        if (pc_info_encode(c->device_id,c->identity_public,body,sizeof(body),&size)!=PC_OK) return PC_INVALID;
        uint8_t base[1024];size_t base_n=size;memcpy(base,body,size);
        if(pc_media_reply_info(base,base_n,body,sizeof(body),&size)!=PC_OK)return PC_INVALID;
        type="application/x-apple-binary-plist"; status=200;
    }
    else if (equal(r.method,"SETUP")) {
        if(c->phase!=PC_CONTROL_VERIFIED || !c->media)status=401;
        else {
            unsigned initial=c->media->phase==0;
            int result=pc_media_setup(c->media,&c->pair,&c->fairplay,r.body.data,r.body.size,body,sizeof(body),&size);
            if(result==PC_OK){
                if(initial && c->media->combined_info){
                    uint8_t info[1024];size_t info_n=0;
                    if(pc_info_encode(c->device_id,c->identity_public,info,sizeof(info),&info_n)!=PC_OK ||
                       pc_media_combine(info,info_n,body,sizeof(body),&size)!=PC_OK)return PC_INVALID;
                }
                status=200;type="application/x-apple-binary-plist";
            }else{
                pc_session_offer_describe(r.body.data,r.body.size);
                status=400;
            }
        }
    }else if(equal(r.method,"GET_PARAMETER") && c->phase==PC_CONTROL_VERIFIED && c->media && c->media->phase>=1) {
        if(equal(r.body,"volume\r\n")) {
            int count=snprintf((char *)body,sizeof(body),"volume: %.6f\r\n",c->media->audio.volume_db);
            if(count<1 || (size_t)count>=sizeof(body))return PC_INVALID;
            size=(size_t)count;type="text/parameters";status=200;
        } else if(!r.body.size) status=200;
    }else if(equal(r.method,"SET_PARAMETER") && c->phase==PC_CONTROL_VERIFIED && c->media && c->media->phase>=1){
        struct pc_span content;
        if(pc_rtsp_header(&r,"Content-Type",&content)==PC_OK && equal(content,"text/parameters") &&
           pc_audio_volume(&c->media->audio,r.body.data,r.body.size)==PC_OK)status=200;
    }else if(equal(r.method,"RECORD") && !r.body.size && c->phase==PC_CONTROL_VERIFIED && c->media && c->media->phase>=1){
        c->media->recording=1;
        /* Modern sender starts the control session before stream allocation. */
        static const uint8_t empty_plist[]={98,112,108,105,115,116,48,48,208,8,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9};
        memcpy(body,empty_plist,sizeof(empty_plist));size=sizeof(empty_plist);
        type="application/x-apple-binary-plist";status=200;
    }
    else if(equal(r.method,"POST") && equal(r.target,"/feedback") && c->phase==PC_CONTROL_VERIFIED)status=200;
    /* Experiment (PICAST_ACCEPT_APP_VIDEO): AirPlay video from apps, not mirroring, is not
     * supported; this accepts its first requests to see what a sender asks next. */
    else if(getenv("PICAST_ACCEPT_APP_VIDEO") && c->phase==PC_CONTROL_VERIFIED && c->media && c->media->phase>=1 &&
            (equal(r.method,"FLUSH") || (equal(r.method,"POST") && equal(r.target,"/audioMode"))))status=200;
    else if(equal(r.method,"TEARDOWN") && c->phase==PC_CONTROL_VERIFIED && c->media){
        int result=pc_media_teardown(c->media,r.body.data,r.body.size);
        if(result==PC_OK)status=200;
        else if(result==PC_OTHER){status=200;c->phase=PC_CONTROL_CLOSED;}
        else status=400;
    }
    else if (equal(r.method,"POST") && equal(r.target,"/fp-setup")) {
        /* Wire negotiation is distinct from media-key decryption. Only the
         * optional media build connects this state to the decoder. */
        if (c->phase==PC_CONTROL_VERIFIED) {
            int fp=pc_fairplay_wire(&c->fairplay,r.body.data,r.body.size,body,sizeof(body),&size);
            if (fp==PC_OK) { status=200; type="application/octet-stream"; }
            else if (fp==PC_INVALID) status=400;
        }
    }
    else if (equal(r.method,"POST") && equal(r.target,"/pair-pin-start")) {
        /* Senders ask again after a cancelled dialog or a mistyped code. Each
         * attempt gets a fresh code, so retries give no guessing advantage. */
        if (c->phase==PC_CONTROL_NEW && c->show_pin && !r.body.size) {
            pc_pin_clear(&c->pin);
            status=show_fresh_pin(c) ? 401 : 200;
        }
    } else if (equal(r.method,"POST") && equal(r.target,"/pair-setup-pin")) {
        /* No valid code: the attempts ran out, or the receiver restarted while the
         * sender's dialog stayed open. Show one, or no entry could ever succeed. */
        if (c->phase==PC_CONTROL_NEW && c->show_pin && !c->pin.phase) show_fresh_pin(c);
        if (c->phase!=PC_CONTROL_NEW || !c->show_pin) status=401;
        else if (pc_pin_request(&c->pin,r.body.data,r.body.size,c->identity_public,body,sizeof(body),&size)) {
            /* Wrong code: keep the connection, so the sender gets this answer
             * and can show its error. The screen always shows the valid code. */
            status=401; pin_retry=1;
            if (!c->pin.phase) show_fresh_pin(c);
        } else {
            type="application/x-apple-binary-plist"; status=200;
            if (c->pin.phase==4) {
                if (pc_pair_init(&c->pair,c->identity_seed,c->pin.peer_key)) status=401;
                else {
                    c->phase=PC_CONTROL_PAIRED;
                    if (c->state_dir && pc_pairing_remember(c->state_dir,c->pin.peer_key)) fputs("Pairing not stored\n",stderr);
                }
            }
        }
    }
    else if (equal(r.method,"POST") && equal(r.target,"/pair-setup")) {
        if (c->phase!=PC_CONTROL_NEW || !c->allow_transient) status=401;
        else if (r.body.size!=32) status=400;
        else if (pc_pair_init(&c->pair,c->identity_seed,r.body.data)) status=401;
        else {
            memcpy(body,c->identity_public,32); size=32; type="application/octet-stream";
            c->phase=PC_CONTROL_PAIRED; status=200;
        }
    } else if (equal(r.method,"POST") && equal(r.target,"/pair-verify")) {
        /* A sender paired in an earlier session goes straight to verify. */
        if (c->phase==PC_CONTROL_NEW && r.body.size==68 && pc_pairing_known(c->state_dir,r.body.data+36) &&
            !pc_pair_init(&c->pair,c->identity_seed,r.body.data+36)) c->phase=PC_CONTROL_PAIRED;
        if (c->phase!=PC_CONTROL_PAIRED) status=401;
        else if (c->pair.phase==PC_PAIR_READY && !pc_pair_begin(&c->pair,r.body.data,r.body.size,body)) {
            size=96; type="application/octet-stream"; status=200;
        } else if (c->pair.phase==PC_PAIR_WAITING && !pc_pair_finish(&c->pair,r.body.data,r.body.size)) {
            c->phase=PC_CONTROL_VERIFIED; type="application/octet-stream"; status=200;
        } else status=401;
    }
    if ((status==400 || status==401) && !pin_retry) {
        pc_pair_clear(&c->pair); c->phase=PC_CONTROL_CLOSED;
        pc_pin_clear(&c->pin);
    }
    /* What a sender asks for and we lack: method and path only, never a query or body. */
    if((status>=400 && status!=401) || (getenv("PICAST_ACCEPT_APP_VIDEO") && !equal(r.target,"/feedback"))){
        printf("{\"event\":\"native_request_refused\",\"status\":%d,\"bytes\":%zu,\"request\":\"",status,r.body.size);
        for(size_t i=0;i<r.method.size;i++)if(r.method.data[i]>='A' && r.method.data[i]<='Z')putchar(r.method.data[i]);
        putchar(' ');
        for(size_t i=0;i<r.target.size && r.target.data[i]!='?';i++){
            char ch=(char)r.target.data[i];
            if((ch>='a' && ch<='z') || (ch>='A' && ch<='Z') || (ch>='0' && ch<='9') || ch=='/' || ch=='-' || ch=='_' || ch=='.')putchar(ch);
        }
        puts("\"}");
    }
    int result=pc_rtsp_response(&r,status,type,body,size,response,capacity,written);
    OPENSSL_cleanse(body,sizeof(body));
    if (result!=PC_OK) { pc_control_clear(c); return result; }
    *consumed=r.consumed; return PC_OK;
}

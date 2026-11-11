/* Independent-client bridge for the real RTSP control state machine. Tests
 * fragmented framing and reconnects without radio, console or real trust. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "picast_control.h"
#include <openssl/srp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static char displayed[5];
static int show(const char code[5]){memcpy(displayed,code,5);return 0;}
static int fail_display(const char code[5]){(void)code;return -1;}
static void hex(const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
static unsigned request(struct pc_control *c,const char *path,const uint8_t *body,size_t n,uint8_t *out,size_t *length){
    uint8_t wire[1400],response[2048];int header=snprintf((char *)wire,sizeof(wire),"POST %s RTSP/1.0\r\nCSeq: 0\r\nContent-Length: %zu\r\n\r\n",path,n);
    assert(header>0 && (size_t)header+n<=sizeof(wire));memcpy(wire+header,body,n);size_t total=(size_t)header+n,written=0,consumed=0;
    for(size_t i=0;i<total;i++)assert(pc_control_request(c,wire,i,response,sizeof(response),&written,&consumed)==PC_OTHER && !written && !consumed);
    assert(pc_control_request(c,wire,total,response,sizeof(response),&written,&consumed)==PC_OK && consumed==total);
    unsigned status=(unsigned)(response[9]-'0')*100+(unsigned)(response[10]-'0')*10+(unsigned)(response[11]-'0');
    size_t begin=0;for(size_t i=0;i+3<written;i++)if(!memcmp(response+i,"\r\n\r\n",4)){begin=i+4;break;}
    assert(begin);*length=written-begin;memcpy(out,response+begin,*length);return status;
}
int main(void){
    struct pc_control c;uint8_t seed[32]={17},reply[1024];size_t size=0;
    assert(pc_control_init(&c,seed,0)==PC_OK);
    assert(request(&c,"/pair-pin-start",(const uint8_t *)"",0,reply,&size)==501 && !c.pin.phase);
    c.show_pin=fail_display;assert(request(&c,"/pair-pin-start",(const uint8_t *)"",0,reply,&size)==401 && c.phase==PC_CONTROL_CLOSED && !c.pin.phase);
    pc_control_clear(&c);assert(pc_control_init(&c,seed,0)==PC_OK);c.show_pin=show;
    assert(request(&c,"/pair-pin-start",(const uint8_t *)"",0,reply,&size)==200 && !size && c.pin.phase==1);
    assert(pc_control_reconnect(&c)==PC_OK && c.pin.phase==1 && !strcmp(c.pin.code,displayed));
    char *n=BN_bn2hex(SRP_get_default_gN("2048")->N);printf("%s %s ",n,displayed);hex(c.identity_public,32);putchar('\n');OPENSSL_free(n);fflush(stdout);
    for(unsigned step=0;step<32;step++){
        char line[8194];if(!fgets(line,sizeof(line),stdin))break;
        size_t bytes=strcspn(line,"\n")/2;assert(bytes<=1024);uint8_t input[1024];
        for(size_t i=0;i<bytes;i++){unsigned v;assert(sscanf(line+i*2,"%2x",&v)==1);input[i]=(uint8_t)v;}
        int unpaired=c.phase==PC_CONTROL_NEW;
        if(request(&c,"/pair-setup-pin",input,bytes,reply,&size)!=200){
            /* A valid code stays on screen after a mistype; a finished pairing cannot be replayed. */
            if(unpaired)assert(c.phase==PC_CONTROL_NEW);
            else assert(c.phase==PC_CONTROL_CLOSED && !c.pin.phase);
            puts("rejected");fflush(stdout);continue;}
        hex(reply,size);putchar('\n');fflush(stdout);
        if(c.pin.phase==4){
            uint8_t expected[32];memset(expected,0x42,32);assert(!memcmp(c.pin.peer_key,expected,32));
            assert(c.phase==PC_CONTROL_PAIRED);assert(pc_control_reconnect(&c)==PC_OK && c.phase==PC_CONTROL_PAIRED && c.pair.phase==PC_PAIR_READY);
        }
    }
    pc_control_clear(&c);assert(!c.pin.phase && !c.pin.srp.private_state);return 0;
}

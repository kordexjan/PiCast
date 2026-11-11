#include "picast_clock.h"
#include <assert.h>
#include <stdio.h>
#define Q UINT64_C(4294967296)
#define NS UINT64_C(1000000000)
int main(void) {
    struct pc_clock c={0};uint64_t value=42;
    assert(pc_clock_video_ntp(0)==(UINT64_C(2208988800)<<32));
    assert(pc_clock_video_ntp(UINT64_MAX-(UINT64_C(2208988800)<<32)+1)==0);
    assert(pc_clock_local(&c,0,0,&value)<0 && value==42);
    /* Exact binary fractions: 1/8s remote processing, 1/8s network RTT. */
    assert(!pc_clock_observe(&c,10*NS,10*NS+NS/4,100*Q,100*Q+Q/8));
    assert(!pc_clock_local(&c,100*Q+Q/8,11*NS,&value));
    assert(value==10*NS+3*NS/16);
    assert(!pc_clock_local(&c,99*Q+Q/8,11*NS,&value));
    assert(value==9*NS+3*NS/16);
    assert(!pc_clock_local(&c,100*Q,16*NS,&value)); /* older sample still usable */
    assert(pc_clock_local(&c,100*Q,41*NS,&value)<0); /* stale */
    assert(pc_clock_local(&c,200*Q,11*NS,&value)<0); /* jump */
    assert(pc_clock_observe(&c,2,1,0,0)<0);
    assert(pc_clock_observe(&c,0,NS,0,0)<0);
    assert(pc_clock_observe(&c,0,NS/4,Q,Q-1)<0);
    assert(pc_clock_observe(&c,0,NS/4,Q,2*Q)<0);
    assert(c.count==1); /* invalid packets cannot perturb the estimate */
    /* Different sender epoch, NTP wrap, RTP wrap, and negative RTP offsets. */
    c=(struct pc_clock){0};
    assert(!pc_clock_observe(&c,20*NS,20*NS+NS/4,UINT64_MAX-Q/16+1,Q/16));
    assert(!pc_clock_local(&c,Q/16,21*NS,&value));
    assert(value==20*NS+3*NS/16);
    assert(!pc_clock_rtp(44099,UINT32_MAX,5*Q,44100,&value) && value==6*Q);
    assert(!pc_clock_rtp(UINT32_MAX,44099,5*Q,44100,&value) && value==4*Q);
    assert(pc_clock_rtp(0,0,0,0,&value)<0);
    assert(pc_clock_rtp(1000000,0,0,44100,&value)<0);
    /* An inflated RTT must not replace the best recent observation. */
    assert(!pc_clock_observe(&c,20*NS,20*NS+NS/2,7*Q,7*Q));
    assert(!pc_clock_local(&c,Q/16,21*NS,&value) && value==20*NS+3*NS/16);
    for(unsigned i=0;i<100000;i++)assert(!pc_clock_observe(&c,30*NS+i*NS,30*NS+i*NS+NS/8,(uint64_t)i*Q,(uint64_t)i*Q));
    assert(c.count==8 && c.next<8);
    c=(struct pc_clock){0};
    uint8_t reply[33]={0x80,0xd3};reply[15]=7;reply[19]=100;reply[27]=100;
    for(size_t n=0;n<32;n++)assert(pc_clock_reply(&c,7,NS,NS+NS/8,reply,n)<0);
    assert(pc_clock_reply(&c,7,NS,NS+NS/8,reply,33)<0);
    assert(pc_clock_reply(&c,8,NS,NS+NS/8,reply,32)<0 && c.count==0);
    reply[1]=0xd2;assert(pc_clock_reply(&c,7,NS,NS+NS/8,reply,32)<0);reply[1]=0xd3;
    assert(!pc_clock_reply(&c,7,NS,NS+NS/8,reply,32) && c.count==1);
    puts("media clock: epochs, rollovers, stale/jump rejection, RTT filtering, bounded long-run storage passed");
}

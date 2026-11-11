#include "picast_clock.h"
#include <stddef.h>
#define NS UINT64_C(1000000000)
#define Q UINT64_C(4294967296)
uint64_t pc_clock_video_ntp(uint64_t raw){return raw+(UINT64_C(2208988800)<<32);}
static uint64_t be64(const uint8_t *p){uint64_t n=0;for(unsigned i=0;i<8;i++)n=n<<8|p[i];return n;}
int pc_clock_reply(struct pc_clock *c,uint64_t token,uint64_t sent,uint64_t received,
                   const uint8_t *p,size_t size) {
    if(!p || size!=32 || p[0]!=0x80 || p[1]!=0xd3 || be64(p+8)!=token)return -1;
    return pc_clock_observe(c,sent,received,be64(p+16),be64(p+24));
}
/* Timing replies can go missing for seconds under load (r168), while the two
 * clocks drift by only microseconds per second: an older sample is still far
 * better than none. Beyond this horizon, treat the jump as a discontinuity. */
#define CLOCK_HORIZON_SECONDS 30U
/* Unsigned modular subtraction also handles the NTP seconds-field rollover. */
static int delta_ns(uint64_t end, uint64_t start, int64_t *out) {
    uint64_t d=end-start;
    int negative=d>UINT64_MAX/2;
    uint64_t magnitude=negative ? (~d)+1 : d;
    if(magnitude>CLOCK_HORIZON_SECONDS*Q)return -1;
    uint64_t ns=(magnitude>>32)*NS+((magnitude&UINT32_MAX)*NS>>32);
    *out=negative ? -(int64_t)ns : (int64_t)ns;
    return 0;
}
int pc_clock_observe(struct pc_clock *c,uint64_t sent,uint64_t received,
                     uint64_t remote_receive,uint64_t remote_send) {
    int64_t processing;
    if(!c || received<sent || received-sent>NS/2 ||
       remote_send-remote_receive>UINT64_MAX/2 ||
       delta_ns(remote_send,remote_receive,&processing) || processing<0 ||
       (uint64_t)processing>received-sent)return -1;
    uint64_t delay=received-sent-(uint64_t)processing;
    struct pc_clock_sample s={remote_send,sent+(received-sent)/2+(uint64_t)processing/2,delay};
    c->samples[c->next]=s;c->next=(c->next+1)%8;
    if(c->count<8)c->count++;
    return 0;
}
int pc_clock_local(const struct pc_clock *c,uint64_t remote,uint64_t now,uint64_t *local) {
    if(!c || !local || !c->count || c->count>8)return -1;
    const struct pc_clock_sample *best=NULL;
    for(unsigned i=0;i<c->count;i++) {
        const struct pc_clock_sample *s=&c->samples[i];
        if(now<s->local_ns || now-s->local_ns>CLOCK_HORIZON_SECONDS*NS)continue;
        if(!best || s->delay_ns<best->delay_ns ||
           (s->delay_ns==best->delay_ns && s->local_ns>best->local_ns))best=s;
    }
    int64_t difference;
    if(!best || delta_ns(remote,best->remote,&difference))return -1;
    if(difference<0) {
        if(best->local_ns<(uint64_t)-difference)return -1;
        *local=best->local_ns-(uint64_t)-difference;
    } else {
        if(UINT64_MAX-best->local_ns<(uint64_t)difference)return -1;
        *local=best->local_ns+(uint64_t)difference;
    }
    return 0;
}
int pc_clock_rtp(uint32_t rtp,uint32_t anchor,uint64_t ntp,unsigned rate,uint64_t *remote) {
    if(!remote || rate<8000 || rate>192000)return -1;
    uint32_t raw=rtp-anchor;
    int64_t ticks=raw<=INT32_MAX ? (int64_t)raw : -(int64_t)((~raw)+1U);
    if(ticks>10*(int64_t)rate || ticks< -10*(int64_t)rate)return -1;
    uint64_t magnitude=(uint64_t)(ticks<0 ? -ticks : ticks);
    uint64_t d=(magnitude/rate)*Q+(magnitude%rate)*Q/rate;
    *remote=ticks<0 ? ntp-d : ntp+d;
    return 0;
}

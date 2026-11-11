#include "picast_trace.h"
#include "picast.h"
int pc_trace_init(struct pc_trace *t,FILE *f,size_t limit,int soft) {
    if(!t || !f || limit<24 || limit>64U*1024U*1024U || (soft!=0 && soft!=1))return PC_INVALID;
    uint8_t header[24];
    if(pc_pcap_header(header,127)!=PC_OK || fwrite(header,1,24,f)!=24)return PC_INVALID;
    *t=(struct pc_trace){.stream=f,.limit=limit,.bytes=24,.soft_limit=(unsigned)soft};return PC_OK;
}
int pc_trace_room(const struct pc_trace *t,size_t n) {
    return t && t->stream && !t->saturated && n<=65535 &&
        t->bytes<=t->limit && t->limit-t->bytes>=16 && n<=t->limit-t->bytes-16;
}
int pc_trace_write(struct pc_trace *t,uint32_t sec,uint32_t usec,const uint8_t *p,size_t n) {
    uint8_t header[16];
    if(!t || !t->stream || !p || pc_pcap_record(header,sec,usec,n)!=PC_OK)return PC_INVALID;
    if(!pc_trace_room(t,n)) {
        if(!t->soft_limit)return PC_INVALID;
        t->saturated=1;
        if(t->skipped<SIZE_MAX)t->skipped++;
        return PC_OK;
    }
    if(fwrite(header,1,16,t->stream)!=16 || fwrite(p,1,n,t->stream)!=n)return PC_INVALID;
    t->bytes+=16+n;return PC_OK;
}

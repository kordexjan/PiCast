#include "picast_mirror.h"
#include <string.h>

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
int pc_mirror_header_parse(const uint8_t *p,size_t n,struct pc_mirror_header *out) {
    if (!p || !out) return PC_INVALID;
    if (n<PC_MIRROR_HEADER_SIZE) return PC_OTHER;
    /* Current Apple senders mark IDR video as wire type 0x1000. Keep the
     * observed flag separate from the actual payload kind. Streaming reports
     * (kind 5) carry no encrypted video bytes. */
    struct pc_mirror_header h={.payload_size=le32(p),.type=p[4],.flags=(uint16_t)(p[6]|p[7]<<8),.type_flags=(uint16_t)p[5]<<8};
    h.ntp=(uint64_t)le32(p+8)|((uint64_t)le32(p+12)<<32);
    if (h.payload_size>PC_MIRROR_MAX_PAYLOAD) return PC_INVALID;
    if (h.type!=0 && h.type!=1 && h.type!=2 && h.type!=5) return PC_UNSUPPORTED;
    if (h.type_flags && !(h.type==0 && h.type_flags==0x1000)) return PC_UNSUPPORTED;
    if (h.type==5 && h.payload_size>65536) return PC_INVALID;
    if ((h.type==2 && h.payload_size) || ((h.type==0 || h.type==1) && !h.payload_size)) return PC_INVALID;
    *out=h; return PC_OK;
}

#define PC_H264_SPS_MAX 300U
struct nal { const uint8_t *p; size_t n; };
static int add_nal(struct nal *nals,size_t *count,const uint8_t *p,size_t n,unsigned type) {
    if (!n || (p[0]&0x80) || !(p[0]&31) || (p[0]&31)>23) return PC_INVALID;
    if (type && (p[0]&31)!=type) return PC_INVALID;
    if (*count>=PC_H264_MAX_NALS) return PC_UNSUPPORTED;
    nals[*count]=(struct nal){p,n}; (*count)++; return PC_OK;
}
static int output_nals(const struct nal *nals,size_t count,uint8_t *out,size_t cap,size_t *written) {
    size_t needed=0;
    for (size_t i=0;i<count;i++) {
        if (nals[i].n>cap || needed>cap-nals[i].n || cap-needed-nals[i].n<4) return PC_INVALID;
        needed+=4+nals[i].n;
    }
    size_t pos=0;
    for (size_t i=0;i<count;i++) {
        memcpy(out+pos,"\0\0\0\1",4);pos+=4;
        memcpy(out+pos,nals[i].p,nals[i].n);pos+=nals[i].n;
    }
    *written=needed;return PC_OK;
}
static int parameter_sets(const uint8_t *p,size_t n,size_t *pos,unsigned amount,unsigned type,
                           struct nal *nals,size_t *count) {
    for (unsigned i=0;i<amount;i++) {
        if (n-*pos<2) return PC_INVALID;
        size_t length=(size_t)p[*pos]*256+p[*pos+1];*pos+=2;
        if (length>n-*pos) return PC_INVALID;
        int rc=add_nal(nals,count,p+*pos,length,type);if (rc!=PC_OK) return rc;
        *pos+=length;
    }
    return PC_OK;
}
/* Bit reader over an SPS with emulation prevention removed. */
struct bits { const uint8_t *p; size_t n, at; int bad; };
static unsigned bits_u(struct bits *b,unsigned count){
    unsigned v=0;
    for(unsigned i=0;i<count;i++){
        if(b->at>=b->n*8){b->bad=1;return 0;}
        v=v<<1|((b->p[b->at/8]>>(7-b->at%8))&1U);b->at++;
    }
    return v;
}
static unsigned bits_ue(struct bits *b){
    unsigned zeros=0;
    while(!b->bad && !bits_u(b,1))if(++zeros>31){b->bad=1;return 0;}
    return zeros ? (1U<<zeros)-1+bits_u(b,zeros) : 0;
}
static void hrd_skip(struct bits *b){
    unsigned count=bits_ue(b);
    if(count>31){b->bad=1;return;}
    (void)bits_u(b,8);
    for(unsigned i=0;i<=count && !b->bad;i++){(void)bits_ue(b);(void)bits_ue(b);(void)bits_u(b,1);}
    (void)bits_u(b,20);
}
static void put_bit(uint8_t *raw,size_t *at,unsigned bit){
    if(!(*at%8))raw[*at/8]=0;
    if(bit)raw[*at/8]|=(uint8_t)(0x80U>>(*at%8));
    (*at)++;
}
static void put_ue(uint8_t *raw,size_t *at,unsigned value){
    unsigned code=value+1,width=0;
    while(code>>(width+1))width++;
    for(unsigned i=0;i<width;i++)put_bit(raw,at,0);
    for(unsigned i=width+1;i-->0;)put_bit(raw,at,(code>>i)&1U);
}
/* iOS omits bitstream_restriction, so a decoder must allow for reordering and may
 * hold pictures until its whole buffer is full. Mirrored streams have no B-frames:
 * declare that. Anything unexpected returns the input unchanged. */
static size_t sps_low_delay(const uint8_t *sps,size_t n,uint8_t *out,size_t cap){
    enum { MAX_SPS=256 };
    uint8_t raw[MAX_SPS];size_t raw_n=0;unsigned zeros=0;
    if(n<4 || n-1>sizeof(raw) || cap<n)return 0;
    for(size_t i=1;i<n;i++){
        if(zeros>=2 && sps[i]==3){zeros=0;continue;}
        raw[raw_n++]=sps[i];zeros=sps[i] ? 0 : zeros+1;
    }
    struct bits b={raw,raw_n,0,0};
    unsigned profile=bits_u(&b,8);(void)bits_u(&b,16);(void)bits_ue(&b);
    if(profile==100 || profile==110 || profile==122 || profile==244){
        if(bits_ue(&b)==3)(void)bits_u(&b,1);
        (void)bits_ue(&b);(void)bits_ue(&b);(void)bits_u(&b,1);
        if(bits_u(&b,1))return 0; /* scaling lists: not seen from iOS */
    }else if(profile!=66 && profile!=77)return 0;
    (void)bits_ue(&b);
    unsigned order=bits_ue(&b);
    if(order==0)(void)bits_ue(&b);else if(order==1)return 0;
    unsigned refs=bits_ue(&b);(void)bits_u(&b,1);(void)bits_ue(&b);(void)bits_ue(&b);
    if(!bits_u(&b,1))(void)bits_u(&b,1);
    (void)bits_u(&b,1);
    if(bits_u(&b,1))for(unsigned i=0;i<4;i++)(void)bits_ue(&b);
    if(!bits_u(&b,1))return 0; /* no VUI: not seen from iOS */
    if(bits_u(&b,1) && bits_u(&b,8)==255)(void)bits_u(&b,32);
    if(bits_u(&b,1))(void)bits_u(&b,1);
    if(bits_u(&b,1)){(void)bits_u(&b,4);if(bits_u(&b,1))(void)bits_u(&b,24);}
    if(bits_u(&b,1)){(void)bits_ue(&b);(void)bits_ue(&b);}
    if(bits_u(&b,1)){(void)bits_u(&b,32);(void)bits_u(&b,32);(void)bits_u(&b,1);}
    unsigned nal=bits_u(&b,1);if(nal)hrd_skip(&b);
    unsigned vcl=bits_u(&b,1);if(vcl)hrd_skip(&b);
    if(nal || vcl)(void)bits_u(&b,1);
    (void)bits_u(&b,1);
    size_t flag=b.at;
    if(b.bad || bits_u(&b,1) || b.bad || refs>16 || flag/8+8>sizeof(raw))return 0; /* already present */
    size_t at=flag;
    raw[flag/8]&=(uint8_t)~(0xFFU>>(flag%8));
    put_bit(raw,&at,1);put_bit(raw,&at,1);
    put_ue(raw,&at,0);put_ue(raw,&at,0);put_ue(raw,&at,16);put_ue(raw,&at,16);
    put_ue(raw,&at,0);put_ue(raw,&at,refs);
    put_bit(raw,&at,1);
    while(at%8)put_bit(raw,&at,0);
    size_t used=at/8,pos=0;
    if(cap<1)return 0;
    out[pos++]=sps[0];zeros=0;
    for(size_t i=0;i<used;i++){
        if(zeros>=2 && raw[i]<=3){if(pos>=cap)return 0;out[pos++]=3;zeros=0;}
        if(pos>=cap)return 0;
        out[pos++]=raw[i];zeros=raw[i] ? 0 : zeros+1;
    }
    return pos;
}
int pc_h264_config_decode(const uint8_t *p,size_t n,struct pc_h264_config *config,
                          uint8_t *out,size_t cap,size_t *written) {
    if (!written) return PC_INVALID;
    *written=0;
    if (!p || !config || !out || n<7 || n>65536) return PC_INVALID;
    if (p[0]!=1) return PC_UNSUPPORTED;
    if ((p[4]&0xfc)!=0xfc || (p[5]&0xe0)!=0xe0) return PC_INVALID;
    unsigned width=(p[4]&3)+1;
    if (width==3) return PC_UNSUPPORTED;
    unsigned sps=p[5]&31;
    if (!sps) return PC_INVALID;
    struct nal nals[PC_H264_MAX_NALS];size_t count=0,pos=6;
    int rc=parameter_sets(p,n,&pos,sps,7,nals,&count);if (rc!=PC_OK) return rc;
    if (pos>=n || !p[pos]) return PC_INVALID;
    unsigned pps=p[pos++];
    rc=parameter_sets(p,n,&pos,pps,8,nals,&count);if (rc!=PC_OK) return rc;
    if (pos<n) {
        /* AVC high-profile extension: preserve SPS extension NALs, and reject
         * unexplained trailing bytes instead of feeding them to the decoder. */
        if (!(p[1]==100 || p[1]==110 || p[1]==122 || p[1]==144)) return PC_UNSUPPORTED;
        /* iOS ends its High-profile config with 02 00 00 00, without the
         * extension's reserved bits. Nothing here reaches the decoder, and
         * the parameter sets above are already complete. */
        static const uint8_t ios_trailer[4]={2,0,0,0};
        if (n-pos==sizeof(ios_trailer) && !memcmp(p+pos,ios_trailer,sizeof(ios_trailer))) pos=n;
        else {
            if (n-pos<4 || (p[pos]&0xfc)!=0xfc || (p[pos+1]&0xf8)!=0xf8 || (p[pos+2]&0xf8)!=0xf8) return PC_INVALID;
            unsigned ext=p[pos+3];pos+=4;
            rc=parameter_sets(p,n,&pos,ext,13,nals,&count);if (rc!=PC_OK) return rc;
        }
    }
    if (pos!=n) return PC_INVALID;
    uint8_t rewritten[PC_H264_SPS_MAX];
    if (count && (nals[0].p[0]&31)==7) {
        size_t size=sps_low_delay(nals[0].p,nals[0].n,rewritten,sizeof(rewritten));
        if (size) nals[0]=(struct nal){rewritten,size};
    }
    rc=output_nals(nals,count,out,cap,written);
    if (rc==PC_OK) config->length_bytes=width;
    return rc;
}
int pc_h264_access_unit(const struct pc_h264_config *config,const uint8_t *p,size_t n,
                         uint8_t *out,size_t cap,size_t *written) {
    if (!written) return PC_INVALID;
    *written=0;
    if (!config || !p || !out || !n || n>PC_MIRROR_MAX_PAYLOAD) return PC_INVALID;
    unsigned width=config->length_bytes;
    if (width!=1 && width!=2 && width!=4) return PC_UNSUPPORTED;
    struct nal nals[PC_H264_MAX_NALS];size_t count=0,pos=0;
    while (pos<n) {
        if (n-pos<width) return PC_INVALID;
        size_t length=0;
        for (unsigned i=0;i<width;i++) length=length*256+p[pos++];
        if (length>n-pos) return PC_INVALID;
        int rc=add_nal(nals,&count,p+pos,length,0);if (rc!=PC_OK) return rc;
        pos+=length;
    }
    return output_nals(nals,count,out,cap,written);
}

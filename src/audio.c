/* Original bounded RTP/AAC-LC receive path. Standard OpenSSL and GStreamer
 * provide CBC and AAC/ALSA primitives; no receiver implementation imported. */
#include "picast_audio.h"
#include "picast.h"
#include "picast_clock.h"
#include "picast_playout.h"
#include <gst/app/gstappsrc.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <math.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
struct audio_output { GstElement *pipeline,*volume;GstAppSrc *input;GstBus *bus;atomic_uint_fast64_t samples; const struct pc_playout *playout;const struct pc_clock *clock; };
static uint32_t be32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static GstPadProbeReturn decoded(GstPad *pad,GstPadProbeInfo *info,gpointer context){
    (void)pad;struct audio_output *o=context;
    if(GST_PAD_PROBE_INFO_TYPE(info)&GST_PAD_PROBE_TYPE_BUFFER){
        GstBuffer *b=GST_PAD_PROBE_INFO_BUFFER(info);
        atomic_fetch_add(&o->samples,gst_buffer_get_size(b)/4);
    }
    return GST_PAD_PROBE_OK;
}
int pc_audio_key(struct pc_audio *a,const uint8_t media[16],const uint8_t shared[32],const uint8_t iv[16]){
    if(!a || !media || !shared || !iv || a->initialized)return PC_INVALID;
    uint8_t input[48],digest[64];unsigned n=0;
    memcpy(input,media,16);memcpy(input+16,shared,32);
    int ok=EVP_Digest(input,48,digest,&n,EVP_sha512(),NULL)==1 && n==64;
    if(ok){memcpy(a->key,digest,16);memcpy(a->iv,iv,16);a->initialized=1;}
    OPENSSL_cleanse(input,sizeof(input));OPENSSL_cleanse(digest,sizeof(digest));return ok ? PC_OK : PC_INVALID;
}
uint64_t pc_audio_decoded(const struct pc_audio *a){
    struct audio_output *o=a ? a->output : NULL;return o ? atomic_load(&o->samples) : 0;
}
void pc_audio_stop(struct pc_audio *a){
    if(!a)return;
    struct audio_output *o=a->output;
    if(o){
        gst_element_set_state(o->pipeline,GST_STATE_NULL);
        gst_object_unref(o->volume);gst_object_unref(o->input);gst_object_unref(o->bus);gst_object_unref(o->pipeline);free(o);
    }
    a->output=NULL;
    OPENSSL_cleanse(a->slots,sizeof(a->slots));
    a->have_sequence=0;a->expected=a->newest=0;
    a->sync_valid=0;a->sync_ntp=0;a->sync_rtp=0;
}
void pc_audio_close(struct pc_audio *a){
    if(!a)return;
    pc_audio_stop(a);
    OPENSSL_cleanse(a,sizeof(*a));
}
int pc_audio_open(struct pc_audio *a,int headless){
    return pc_audio_open_timed(a,headless,NULL,NULL);
}
int pc_audio_open_timed(struct pc_audio *a,int headless,const struct pc_playout *playout,const struct pc_clock *clock){
    if(!a || !a->initialized || a->output)return PC_INVALID;
    if((playout!=NULL)!=(clock!=NULL))return PC_INVALID;
    gst_init(NULL,NULL);GError *error=NULL;
    struct audio_output *o=calloc(1,sizeof(*o));if(!o)return PC_INVALID;
    atomic_init(&o->samples,0);
    o->pipeline=gst_parse_launch(headless ?
        "appsrc name=input format=time is-live=true do-timestamp=true block=false ! faad name=decode ! audioconvert ! volume name=gain ! fakesink name=output sync=false" :
        "appsrc name=input format=time is-live=true do-timestamp=true block=false ! faad name=decode ! audioconvert ! audioresample ! volume name=gain ! alsasink name=output device=plughw:0,0 sync=false buffer-time=100000 latency-time=10000",&error);
    if(!o->pipeline || error){if(o->pipeline)gst_object_unref(o->pipeline);g_clear_error(&error);free(o);return PC_INVALID;}
    o->input=GST_APP_SRC(gst_bin_get_by_name(GST_BIN(o->pipeline),"input"));
    o->volume=gst_bin_get_by_name(GST_BIN(o->pipeline),"gain");o->bus=gst_element_get_bus(o->pipeline);
    if(playout){
        if(pc_playout_attach(playout,o->pipeline)){a->output=o;pc_audio_stop(a);return PC_INVALID;}
        GstElement *sink=gst_bin_get_by_name(GST_BIN(o->pipeline),"output");
        g_object_set(sink,"sync",TRUE,NULL);
        if(!headless)g_object_set(sink,"slave-method",0,"buffer-time",(gint64)40000,NULL);
        gst_object_unref(sink);g_object_set(o->input,"do-timestamp",FALSE,NULL);
        o->playout=playout;o->clock=clock;
    }
    GstElement *decode=gst_bin_get_by_name(GST_BIN(o->pipeline),"decode");GstPad *pad=gst_element_get_static_pad(decode,"src");
    gst_pad_add_probe(pad,GST_PAD_PROBE_TYPE_BUFFER,decoded,o,NULL);gst_object_unref(pad);gst_object_unref(decode);
    GstBuffer *asc=gst_buffer_new_allocate(NULL,2,NULL);const uint8_t config[2]={0x12,0x10};gst_buffer_fill(asc,0,config,2);
    GstCaps *caps=gst_caps_new_simple("audio/mpeg","mpegversion",G_TYPE_INT,4,"stream-format",G_TYPE_STRING,"raw","rate",G_TYPE_INT,44100,"channels",G_TYPE_INT,2,"codec_data",GST_TYPE_BUFFER,asc,NULL);
    gst_buffer_unref(asc);gst_app_src_set_caps(o->input,caps);gst_caps_unref(caps);gst_app_src_set_max_bytes(o->input,65536);
    a->output=o;g_object_set(o->volume,"volume",a->volume_db<=-144 ? 0.0 : pow(10.0,a->volume_db/20.0),NULL);
    if(gst_element_set_state(o->pipeline,GST_STATE_PLAYING)==GST_STATE_CHANGE_FAILURE){pc_audio_close(a);return PC_INVALID;}
    return PC_OK;
}
int pc_audio_sync(struct pc_audio *a,const uint8_t *p,size_t n){
    if(!a || !a->initialized || !p || n!=20 || (p[0]!=0x80 && p[0]!=0x90) ||
       (p[1]&127)!=84 || p[2]!=0 || p[3]!=4)return PC_INVALID;
    uint32_t rtp=be32(p+4),next=be32(p+16);
    if(next-rtp>2U*44100U)return PC_INVALID;
    a->sync_rtp=rtp;a->sync_ntp=(uint64_t)be32(p+8)<<32|be32(p+12);a->sync_valid=1;
    return PC_OK;
}
int pc_audio_ingress(struct pc_audio *a,const uint8_t *p,size_t n){
    if(!a || !a->initialized || !a->output || !p || n<12 || n>1500 || p[0]>>6!=2 || (p[1]&127)!=96)return PC_INVALID;
    size_t start=12U+4U*(p[0]&15);if(start>n)return PC_INVALID;
    if(p[0]&16){if(n-start<4)return PC_INVALID;size_t ext=4U+4U*((size_t)p[start+2]*256+p[start+3]);if(ext>n-start)return PC_INVALID;start+=ext;}
    if(p[0]&32){size_t pad=p[n-1];if(!pad || pad>n-start)return PC_INVALID;n-=pad;}
    if(n<=start)return PC_INVALID;
    uint16_t seq=(uint16_t)((unsigned)p[2]*256+p[3]);
    if(!a->have_sequence){a->expected=a->newest=seq;a->have_sequence=1;}
    int16_t difference=(int16_t)(seq-a->expected);
    if(difference<0){a->duplicates++;return PC_OTHER;}
    if(difference>=(int)PC_AUDIO_WINDOW){
        unsigned retained=0;
        for(unsigned i=0;i<PC_AUDIO_WINDOW;i++)if(a->slots[i].size){
            uint16_t offset=(uint16_t)(a->slots[i].sequence-a->expected);
            if(offset<(unsigned)difference)retained++;
            a->slots[i].size=0;
        }
        a->lost+=(unsigned)difference-retained;a->buffered_dropped+=retained;a->expected=seq;
    }
    struct pc_audio_slot *slot=&a->slots[seq%PC_AUDIO_WINDOW];
    if(slot->size && slot->sequence==seq){a->duplicates++;return PC_OTHER;}
    size_t size=n-start,encrypted=size&~(size_t)15;uint8_t plain[1500];int count=0,ok=1;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
    if(encrypted)ok=ctx && EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,a->key,a->iv)==1 && EVP_CIPHER_CTX_set_padding(ctx,0)==1 &&
        EVP_DecryptUpdate(ctx,plain,&count,p+start,(int)encrypted)==1 && count==(int)encrypted;
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){OPENSSL_cleanse(plain,sizeof(plain));return PC_INVALID;}
    memcpy(plain+encrypted,p+start+encrypted,size-encrypted);
    memcpy(slot->data,plain,size);slot->size=size;slot->sequence=seq;slot->timestamp=be32(p+4);a->received++;
    OPENSSL_cleanse(plain,sizeof(plain));
    if((int16_t)(seq-a->newest)>0)a->newest=seq;
    return PC_OK;
}
int pc_audio_step(struct pc_audio *a){
    struct audio_output *o=a ? a->output : NULL;if(!o)return PC_OK;
    GstMessage *msg=gst_bus_pop_filtered(o->bus,GST_MESSAGE_ERROR);
    if(msg){GError *error=NULL;gchar *detail=NULL;gst_message_parse_error(msg,&error,&detail);fprintf(stderr,"audio decoder/output: %s\n",error ? error->message : "unavailable");g_clear_error(&error);g_free(detail);gst_message_unref(msg);return PC_INVALID;}
    for(unsigned i=0;i<8 && a->have_sequence;i++){
        struct pc_audio_slot *slot=&a->slots[a->expected%PC_AUDIO_WINDOW];
        if(!slot->size || slot->sequence!=a->expected){if((int16_t)(a->newest-a->expected)<8)break;a->lost++;a->expected++;continue;}
        if(gst_app_src_get_current_level_bytes(o->input)>65536)break;
        /* Four-byte silence sentinel carries no coded access unit. */
        if(slot->size!=4 || memcmp(slot->data,"\0\x68\x34\0",4)){
            uint64_t pts=GST_CLOCK_TIME_NONE;
            if(o->playout){
                struct timespec at;clock_gettime(CLOCK_MONOTONIC,&at);
                uint64_t remote,local,now=(uint64_t)at.tv_sec*GST_SECOND+(uint64_t)at.tv_nsec;
                if(!a->sync_valid || pc_clock_rtp(slot->timestamp,a->sync_rtp,a->sync_ntp,44100,&remote) ||
                   pc_clock_local(o->clock,remote,now,&local) || pc_playout_pts(o->playout,local,&pts))break;
                int64_t age=now>=local ? (int64_t)(now-local) : -(int64_t)(local-now);
                if(!a->clock_samples || age<a->ingress_age_min_ns)a->ingress_age_min_ns=age;
                if(!a->clock_samples || age>a->ingress_age_max_ns)a->ingress_age_max_ns=age;
                a->clock_samples++;
                /* Decode-independent AAC access units may be skipped when
                 * their presentation deadline is already gone. Do not queue
                 * old startup sound behind current video or mislabel retained
                 * packets as missing on the network. */
                if(now>local && now-local>o->playout->delay_ns+UINT64_C(40000000)){
                    a->late_dropped++;OPENSSL_cleanse(slot->data,slot->size);slot->size=0;a->expected++;continue;
                }
            }
            GstBuffer *b=gst_buffer_new_allocate(NULL,slot->size,NULL);if(!b)return PC_INVALID;
            gst_buffer_fill(b,0,slot->data,slot->size);GST_BUFFER_DURATION(b)=gst_util_uint64_scale(1024,GST_SECOND,44100);
            GST_BUFFER_PTS(b)=pts;GST_BUFFER_DTS(b)=GST_CLOCK_TIME_NONE;
            if(gst_app_src_push_buffer(o->input,b)!=GST_FLOW_OK)return PC_INVALID;
            a->submitted++;
        }
        OPENSSL_cleanse(slot->data,slot->size);slot->size=0;a->expected++;
    }
    return PC_OK;
}
int pc_audio_end(struct pc_audio *a){
    struct audio_output *o=a ? a->output : NULL;return o && gst_app_src_end_of_stream(o->input)==GST_FLOW_OK ? PC_OK : PC_INVALID;
}
int pc_audio_volume(struct pc_audio *a,const uint8_t *input,size_t n){
    if(!a || !input || n<10 || n>48 || memcmp(input,"volume:",7) || memcmp(input+n-2,"\r\n",2))return PC_INVALID;
    char number[42];size_t size=n-9;if(size>=sizeof(number))return PC_INVALID;memcpy(number,input+7,size);number[size]=0;
    /* Restrict grammar before strtod: no locale-dependent exponent or NaN. */
    size_t pos=0;while(number[pos]==' ')pos++;if(number[pos]=='-')pos++;unsigned digits=0,dots=0;
    for(;pos<size;pos++){if(number[pos]>='0' && number[pos]<='9')digits++;else if(number[pos]=='.')dots++;else return PC_INVALID;}
    if(!digits || dots>1)return PC_INVALID;
    char *end=NULL;double value=strtod(number,&end);
    if(!end || *end || !isfinite(value) || (value!=-144 && (value< -30 || value>0)))return PC_INVALID;
    a->volume_db=value;struct audio_output *o=a->output;
    if(o)g_object_set(o->volume,"volume",value<=-144 ? 0.0 : pow(10.0,value/20.0),NULL);
    return PC_OK;
}

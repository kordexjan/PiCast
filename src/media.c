#include "picast_media.h"
#include "picast_fp_key.h"
#include "picast_session.h"
#include "picast_video_output.h"
#include <plist/plist.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* Delays the picture while sound plays, to match the speakers. The trial sets
 * PICAST_VIDEO_ALIGN_MS: this value depends on the display and is being measured
 * on a real TV, as the capture dongle cannot tell it (r174).
 * Ramping keeps presentation times rising, the faster step when sound starts. */
#define VIDEO_ALIGN_DEFAULT_MS 220U
#define VIDEO_ALIGN_MAX_MS 500U
#define VIDEO_ALIGN_RAISE_NS UINT64_C(10000000)
#define VIDEO_ALIGN_LOWER_NS UINT64_C(2000000)
static uint64_t video_align_target_ns(void){
    const char *text=getenv("PICAST_VIDEO_ALIGN_MS");
    if(text){
        char *end=NULL;unsigned long ms=strtoul(text,&end,10);
        if(end!=text && !*end && ms<=VIDEO_ALIGN_MAX_MS)return ms*UINT64_C(1000000);
    }
    /* Timed pictures share the sound's delay exactly: the sender stamps both on one
     * timeline, so the same offset keeps them together (r227: the extra 220 ms
     * meant for immediate pictures put the picture behind the sound). */
    if(pc_video_timed())return 0;
    return VIDEO_ALIGN_DEFAULT_MS*UINT64_C(1000000);
}
/* Each clock update moves the mapping by a few milliseconds; passed straight on,
 * that shifts pictures off their even spacing on screen. Instead a picture's time
 * follows the previous one by exactly the sender's spacing, and any difference to
 * the clock is worked off at most 1 ms per picture. A jump over 100 ms (a new
 * stream, a lost clock) is taken at once. */
#define SLEW_STEP_NS INT64_C(1000000)
#define SLEW_RESET_NS INT64_C(100000000)
static uint64_t smooth_mapping(struct pc_media *m,uint64_t remote,uint64_t mapped){
    uint64_t d=remote-m->smooth_remote;
    if(m->smooth_valid && d<(UINT64_C(1)<<31)){
        uint64_t expected=m->smooth_mapped+((d*UINT64_C(1000000000))>>32);
        int64_t error=mapped>=expected ? (int64_t)(mapped-expected) : -(int64_t)(expected-mapped);
        if(error>SLEW_RESET_NS || error<-SLEW_RESET_NS)m->clock_resets++;
        else{
            if(error>2*SLEW_STEP_NS || error<-2*SLEW_STEP_NS)m->clock_slews++;
            if(error>SLEW_STEP_NS)error=SLEW_STEP_NS;
            if(error<-SLEW_STEP_NS)error=-SLEW_STEP_NS;
            mapped=error>=0 ? expected+(uint64_t)error : expected-(uint64_t)-error;
        }
    }
    m->smooth_remote=remote;m->smooth_mapped=mapped;m->smooth_valid=1;
    return mapped;
}
/* Arrival age histogram, 10 ms steps from -200 ms, to size the playout buffer. */
static void age_record(struct pc_media *m,int64_t age){
    int64_t bucket=(age/1000000+PC_MEDIA_AGE_FLOOR_MS)/10;
    if(bucket<0)bucket=0;
    if(bucket>=PC_MEDIA_AGE_BUCKETS)bucket=PC_MEDIA_AGE_BUCKETS-1;
    m->video_age_hist[bucket]++;
}
static int age_percentile(const struct pc_media *m,double share){
    uint64_t total=0,seen=0;
    for(unsigned i=0;i<PC_MEDIA_AGE_BUCKETS;i++)total+=m->video_age_hist[i];
    if(!total)return 0;
    for(unsigned i=0;i<PC_MEDIA_AGE_BUCKETS;i++){seen+=m->video_age_hist[i];if(seen>=share*total)return (int)(i*10+10)-PC_MEDIA_AGE_FLOOR_MS;}
    return PC_MEDIA_AGE_BUCKETS*10-PC_MEDIA_AGE_FLOOR_MS;
}
static uint64_t next_video_align(uint64_t align,uint64_t target){
    if(align<target)return target-align<VIDEO_ALIGN_RAISE_NS ? target : align+VIDEO_ALIGN_RAISE_NS;
    return align-target<VIDEO_ALIGN_LOWER_NS ? target : align-VIDEO_ALIGN_LOWER_NS;
}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static uint64_t monotonic_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static uint64_t be64(const uint8_t *p){uint64_t n=0;for(unsigned i=0;i<8;i++)n=n<<8|p[i];return n;}
static int encode(plist_t d,uint8_t *out,size_t cap,size_t *written){
    char *raw=NULL;uint32_t n=0;*written=0;
    int ok=d && plist_to_bin(d,&raw,&n)==PLIST_ERR_SUCCESS && raw && n<=cap;
    if(ok){memcpy(out,raw,n);*written=n;}
    if(raw)plist_mem_free(raw);
    return ok ? PC_OK : PC_INVALID;
}
static plist_t dictionary(const uint8_t *raw,size_t n){
    plist_t d=NULL;
    if(!raw || n<8 || n>4096 || memcmp(raw,"bplist00",8) || plist_from_bin((const char *)raw,(uint32_t)n,&d)!=PLIST_ERR_SUCCESS)return NULL;
    if(!d || plist_get_node_type(d)!=PLIST_DICT || plist_dict_get_size(d)>32){if(d)plist_free(d);return NULL;}
    return d;
}
/* The display's shape (PICAST_SCREEN=WIDTHxHEIGHT, from the runner) within the
 * 1920 x 1080 the decoder takes: a Mac then sends a picture of that shape, 21:9 or
 * 16:10 instead of 16:9. Even sizes; 16:9 without a valid value. */
void pc_media_display_size(const char *screen,unsigned *width,unsigned *height){
    unsigned w=0,h=0;*width=1920;*height=1080;
    if(!screen || sscanf(screen,"%ux%u",&w,&h)!=2 || w<320 || h<240 || w>8192 || h>8192)return;
    double aspect=(double)w/h;
    if(aspect<1.0 || aspect>4.0)return;
    if(aspect>=1920.0/1080){*width=1920;*height=(unsigned)(1920/aspect+0.5)&~1U;}
    else{*height=1080;*width=(unsigned)(1080*aspect+0.5)&~1U;}
}
static void display_info(plist_t root){
    plist_t a=plist_new_array(),d=plist_new_dict();
    unsigned width,height;pc_media_display_size(getenv("PICAST_SCREEN"),&width,&height);
    plist_dict_set_item(d,"uuid",plist_new_string("63736950-7473-4043-8000-000000000001"));
    /* iOS fits its screen inside this size: 720p gave a 332x720 portrait stream. */
    plist_dict_set_item(d,"width",plist_new_uint(width));plist_dict_set_item(d,"height",plist_new_uint(height));
    plist_dict_set_item(d,"widthPixels",plist_new_uint(width));plist_dict_set_item(d,"heightPixels",plist_new_uint(height));
    plist_dict_set_item(d,"widthPhysical",plist_new_uint(0));plist_dict_set_item(d,"heightPhysical",plist_new_uint(0));
    /* 16607 pictures at 1920x884 kept up without a backlog (r212). PICAST_MAX_FPS=30 compares. */
    const char *fps_text=getenv("PICAST_MAX_FPS");unsigned fps=fps_text && !strcmp(fps_text,"30") ? 30 : 60;
    plist_dict_set_item(d,"refreshRate",plist_new_real(1.0/fps));plist_dict_set_item(d,"maxFPS",plist_new_uint(fps));
    plist_dict_set_item(d,"features",plist_new_uint(14));plist_dict_set_item(d,"overscanned",plist_new_bool(0));
    plist_dict_set_item(d,"rotation",plist_new_bool(0));plist_array_append_item(a,d);
    plist_dict_set_item(root,"displays",a);
    plist_dict_set_item(root,"keepAliveLowPower",plist_new_bool(0));
    plist_dict_set_item(root,"keepAliveSendStatsAsBody",plist_new_bool(1));
}
int pc_media_reply_info(const uint8_t *raw,size_t n,uint8_t *out,size_t cap,size_t *written){
    plist_t d=dictionary(raw,n);if(!d)return PC_INVALID;
    display_info(d);int rc=encode(d,out,cap,written);plist_free(d);return rc;
}
int pc_media_combine(const uint8_t *info,size_t n,uint8_t *reply,size_t cap,size_t *size){
    plist_t d=dictionary(info,n),r=dictionary(reply,*size);if(!d || !r){if(d)plist_free(d);if(r)plist_free(r);return PC_INVALID;}
    plist_dict_merge(&d,r);display_info(d);
    int rc=encode(d,reply,cap,size);plist_free(d);plist_free(r);return rc;
}
int pc_media_open(struct pc_media *m,const int sockets[5],const uint8_t peer[6]){
    if(!m || !sockets || !peer)return -1;
    /* First plugin discovery measured up to 0.77s on this Pi. Perform it
     * before radio scheduling starts, rather than while replying to SETUP. */
    pc_video_output_prepare();
    memset(m,0,sizeof(*m));memcpy(m->sockets,sockets,sizeof(m->sockets));memcpy(m->peer,peer,6);
    m->video_client=m->event_client=-1;
    m->packet_limit=4096;m->byte_limit=64U*1024U*1024U;
    {
        /* Shared buffer before sound and timed pictures; tuned per trial on a real TV. */
        uint64_t delay=PC_PLAYOUT_DEFAULT_MS*UINT64_C(1000000);const char *text=getenv("PICAST_PLAYOUT_DELAY_MS");
        if(text){char *end=NULL;unsigned long ms=strtoul(text,&end,10);if(end!=text && !*end && ms<=500)delay=ms*UINT64_C(1000000);}
        if(pc_playout_open(&m->playout,delay))return -1;
    }
    m->payload=malloc(PC_MIRROR_MAX_PAYLOAD);m->annex=malloc(PC_MIRROR_MAX_PAYLOAD+4*PC_H264_MAX_NALS);
    if(m->payload && m->annex)return 0;
    free(m->payload);free(m->annex);m->payload=m->annex=NULL;pc_playout_close(&m->playout);return -1;
}
void pc_media_close(struct pc_media *m){
    if(!m)return;
    unsigned frames=0,width=0,height=0;pc_video_output_stats(m->output,&frames,&width,&height);
    printf("{\"event\":\"native_media_summary\",\"phase\":%u,\"packets\":%u,\"configs\":%u,\"video_packets\":%u,\"decoded_frames\":%u,\"width\":%u,\"height\":%u}\n",m->phase,m->packets,m->configs,m->video_packets,frames,width,height);
    uint64_t rendered,dropped;pc_video_output_delivery_stats(m->output,&rendered,&dropped);
    unsigned crops,crop_w,crop_h;pc_video_output_crop_stats(m->output,&crops,&crop_w,&crop_h);
    unsigned paced,uneven,stalls,worst;pc_video_output_pacing_stats(m->output,&paced,&uneven,&stalls,&worst);
    printf("{\"event\":\"native_video_output_summary\",\"rendered_frames\":%llu,\"late_dropped_frames\":%llu,\"crop_changes\":%u,\"last_crop_width\":%u,\"last_crop_height\":%u,\"paced_frames\":%u,\"uneven_frames\":%u,\"stalled_frames\":%u,\"worst_jitter_ms\":%u,\"timed\":%s}\n",(unsigned long long)rendered,(unsigned long long)dropped,crops,crop_w,crop_h,paced,uneven,stalls,worst,pc_video_timed() ? "true" : "false");
    printf("{\"event\":\"native_video_span_summary\",\"submitted_video_packets\":%u,\"receive_span_ns\":%llu,\"physical_display_duration_measured\":false}\n",m->video_packets,(unsigned long long)(m->last_video_ns-m->first_video_ns));
    printf("{\"event\":\"native_audio_summary\",\"packets\":%u,\"submitted\":%u,\"duplicates\":%u,\"lost\":%u,\"decoded_samples\":%llu}\n",m->audio.received,m->audio.submitted,m->audio.duplicates,m->audio.lost,(unsigned long long)pc_audio_decoded(&m->audio));
    printf("{\"event\":\"native_clock_summary\",\"timing_valid\":%u,\"timing_rejected\":%u,\"video_mapped\":%llu,\"video_unmapped\":%llu,\"video_ingress_age_min_ns\":%lld,\"video_ingress_age_max_ns\":%lld,\"video_age_p50_ms\":%d,\"video_age_p90_ms\":%d,\"video_age_p99_ms\":%d,\"video_age_p999_ms\":%d,\"video_align_ms\":%llu,\"clock_slews\":%u,\"clock_resets\":%u,\"playout_synchronized\":false}\n",m->timing_valid,m->timing_rejected,(unsigned long long)m->video_clock_samples,(unsigned long long)m->video_clock_unmapped,(long long)m->video_age_min_ns,(long long)m->video_age_max_ns,age_percentile(m,0.5),age_percentile(m,0.9),age_percentile(m,0.99),age_percentile(m,0.999),(unsigned long long)(m->video_align_ns/1000000),m->clock_slews,m->clock_resets);
    printf("{\"event\":\"native_playout_summary\",\"timestamped_output_enabled\":%s,\"target_delay_ns\":%llu,\"audio_sync_anchor_received\":%s,\"end_to_end_sync_measured\":false}\n",m->playout.clock ? "true" : "false",(unsigned long long)m->playout.delay_ns,m->audio.sync_valid ? "true" : "false");
    printf("{\"event\":\"native_audio_clock_summary\",\"mapped\":%llu,\"buffered_dropped\":%u,\"late_dropped\":%u,\"ingress_age_min_ns\":%lld,\"ingress_age_max_ns\":%lld}\n",(unsigned long long)m->audio.clock_samples,m->audio.buffered_dropped,m->audio.late_dropped,(long long)m->audio.ingress_age_min_ns,(long long)m->audio.ingress_age_max_ns);
    pc_audio_close(&m->audio);
    pc_video_output_close(m->output);pc_mirror_cipher_clear(&m->cipher);
    pc_playout_close(&m->playout);
    if(m->video_client>=0)close(m->video_client);
    if(m->event_client>=0)close(m->event_client);
    for(unsigned i=0;i<5;i++)if(m->sockets[i]>=0)close(m->sockets[i]);
    if(m->payload){OPENSSL_cleanse(m->payload,PC_MIRROR_MAX_PAYLOAD);free(m->payload);}
    free(m->annex);OPENSSL_cleanse(m,sizeof(*m));
    for(unsigned i=0;i<5;i++)m->sockets[i]=-1;
    m->video_client=m->event_client=-1;
}
static int uint_value(plist_t d,const char *name,uint64_t *value){
    plist_t v=plist_dict_get_item(d,name);if(!v || plist_get_node_type(v)!=PLIST_UINT)return 0;
    plist_get_uint_val(v,value);return 1;
}
int pc_media_teardown(struct pc_media *m,const uint8_t *raw,size_t n){
    if(!m || !m->phase)return PC_INVALID;
    if(!n)return PC_OTHER;
    plist_t request=dictionary(raw,n);if(!request)return PC_INVALID;
    plist_t streams=plist_dict_get_item(request,"streams");
    if(!streams){plist_free(request);return PC_OTHER;}
    uint64_t type=0;
    plist_t stream=plist_get_node_type(streams)==PLIST_ARRAY && plist_array_get_size(streams)==1 ? plist_array_get_item(streams,0) : NULL;
    int audio_only=stream && plist_get_node_type(stream)==PLIST_DICT && uint_value(stream,"type",&type) && type==96;
    plist_free(request);
    if(!audio_only)return PC_INVALID;
    /* Native senders tear down idle audio independently of video. Session
     * authentication, mirror CTR position and the video socket must survive. */
    pc_audio_stop(&m->audio);m->sender_audio_control_port=0;
    return PC_OK;
}
int pc_media_setup(struct pc_media *m,const struct pc_pair_verify *pair,const struct pc_fairplay *fp,
                    const uint8_t *raw,size_t n,uint8_t *out,size_t cap,size_t *size){
    if(!m || !pair || pair->phase!=PC_PAIR_VERIFIED || !fp || fp->phase!=2 || !out || !size || cap<2048)return PC_INVALID;
    plist_t reply=plist_new_dict();int result=PC_INVALID;
    if(!reply)return PC_INVALID;
    if(!m->phase){
        struct pc_session_offer offer;uint8_t key[16]={0},secret[32]={0};
        if(pc_session_offer_parse(raw,n,&offer)!=PC_OK || pc_pair_media_secret(pair,secret) ||
           pc_fp_key_unwrap(fp->key_message,sizeof(fp->key_message),offer.wrapped_key,sizeof(offer.wrapped_key),key)!=PC_OK)goto first_done;
        if(pc_audio_key(&m->audio,key,secret,offer.iv)!=PC_OK)goto first_done;
        plist_dict_set_item(reply,"eventPort",plist_new_uint(37002));
        plist_dict_set_item(reply,"timingPort",plist_new_uint(37003));
        result=encode(reply,out,cap,size);
        if(result==PC_OK){memcpy(m->key,key,16);memcpy(m->shared,secret,32);m->sender_timing_port=offer.sender_timing_port;m->combined_info=offer.combined_info;m->phase=1;}
first_done:
        OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(secret,sizeof(secret));OPENSSL_cleanse(&offer,sizeof(offer));
    }else if(m->phase==1 || m->phase==2){
        plist_t request=dictionary(raw,n);uint64_t type=0,id=0;
        plist_t streams=request ? plist_dict_get_item(request,"streams") : NULL;
        plist_t stream=streams && plist_get_node_type(streams)==PLIST_ARRAY && plist_array_get_size(streams)==1 ? plist_array_get_item(streams,0) : NULL;
        if(stream && plist_get_node_type(stream)==PLIST_DICT && uint_value(stream,"type",&type) && type==110 && m->phase==1 && uint_value(stream,"streamConnectionID",&id)){
            if(pc_mirror_cipher_init(&m->cipher,m->key,m->shared,id)==PC_OK && (m->output=pc_video_output_open_timed(0,m->playout.clock ? &m->playout : NULL))){
                plist_t a=plist_new_array(),d=plist_new_dict();
                plist_dict_set_item(d,"type",plist_new_uint(110));plist_dict_set_item(d,"dataPort",plist_new_uint(37001));
                plist_array_append_item(a,d);plist_dict_set_item(reply,"streams",a);
                plist_dict_set_item(reply,"eventPort",plist_new_uint(37002));plist_dict_set_item(reply,"timingPort",plist_new_uint(37003));
                result=encode(reply,out,cap,size);
                if(result==PC_OK){m->phase=2;OPENSSL_cleanse(m->key,16);OPENSSL_cleanse(m->shared,32);}
            }
        }
        if(stream && plist_get_node_type(stream)==PLIST_DICT && uint_value(stream,"type",&type) && type==96 && !m->audio.output){
            uint64_t ct=0,sr=0,spf=0,format=0,port=0;
            if(uint_value(stream,"ct",&ct) && ct==4 && uint_value(stream,"sr",&sr) && sr==44100 &&
               uint_value(stream,"spf",&spf) && spf==1024 && uint_value(stream,"audioFormat",&format) && format==4194304 &&
               uint_value(stream,"controlPort",&port) && port>=1024 && port<=65535 && pc_audio_open_timed(&m->audio,0,m->playout.clock ? &m->playout : NULL,m->playout.clock ? &m->clock : NULL)==PC_OK){
                plist_t a=plist_new_array(),d=plist_new_dict();plist_dict_set_item(d,"type",plist_new_uint(96));
                plist_dict_set_item(d,"dataPort",plist_new_uint(37004));plist_dict_set_item(d,"controlPort",plist_new_uint(37005));
                plist_array_append_item(a,d);plist_dict_set_item(reply,"streams",a);plist_dict_set_item(reply,"timingPort",plist_new_uint(37003));
                result=encode(reply,out,cap,size);if(result==PC_OK)m->sender_audio_control_port=(uint16_t)port;
            }
        }
        /* Experiment (PICAST_ACCEPT_APP_VIDEO): an app's session asks for a sound stream
         * PiCast does not decode. Accept it without playing, and log its format. */
        if(stream && result!=PC_OK && plist_get_node_type(stream)==PLIST_DICT && uint_value(stream,"type",&type) && type==96 && getenv("PICAST_ACCEPT_APP_VIDEO")){
            uint64_t ct=0,sr=0,spf=0,format=0;
            (void)uint_value(stream,"ct",&ct);(void)uint_value(stream,"sr",&sr);(void)uint_value(stream,"spf",&spf);(void)uint_value(stream,"audioFormat",&format);
            printf("{\"event\":\"app_audio_stream\",\"ct\":%llu,\"sr\":%llu,\"spf\":%llu,\"audio_format\":%llu}\n",(unsigned long long)ct,(unsigned long long)sr,(unsigned long long)spf,(unsigned long long)format);
            plist_t a=plist_new_array(),d=plist_new_dict();plist_dict_set_item(d,"type",plist_new_uint(96));
            plist_dict_set_item(d,"dataPort",plist_new_uint(37004));plist_dict_set_item(d,"controlPort",plist_new_uint(37005));
            plist_array_append_item(a,d);plist_dict_set_item(reply,"streams",a);plist_dict_set_item(reply,"timingPort",plist_new_uint(37003));
            result=encode(reply,out,cap,size);
        }
        if(request)plist_free(request);
    }
    plist_free(reply);return result;
}
static int accept_one(int listener,int *client){
    if(*client>=0)return 0;
    int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
    if(fd<0)return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 0 : -1;
    *client=fd;return 0;
}
static void timestamp(uint8_t out[8]){
    struct timespec t;clock_gettime(CLOCK_REALTIME,&t);
    uint64_t v=((uint64_t)t.tv_sec+UINT64_C(2208988800))<<32 | ((uint64_t)t.tv_nsec<<32)/1000000000;
    for(unsigned i=0;i<8;i++)out[i]=(uint8_t)(v>>(56-8*i));
}
static int timing(struct pc_media *m){
    struct sockaddr_in6 peer={0};socklen_t length=sizeof(peer);uint8_t packet[33];
    ssize_t n=recvfrom(m->sockets[2],packet,sizeof(packet),0,(struct sockaddr *)&peer,&length);
    uint64_t received_ns=monotonic_ns();uint8_t expected_ip[16];pc_linklocal(m->peer,expected_ip);
    if(n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return -1;
    if(n>=0 && (length!=sizeof(peer) || peer.sin6_family!=AF_INET6 || memcmp(peer.sin6_addr.s6_addr,expected_ip,16) || peer.sin6_port!=htons(m->sender_timing_port))){m->timing_rejected++;n=-1;}
    if(n==32 && packet[0]==0x80 && packet[1]==0xd3){
        if(m->timing_pending && !pc_clock_reply(&m->clock,m->timing_token,m->timing_sent_ns,received_ns,packet,32)){
            m->timing_pending=0;m->timing_valid++;
        }else m->timing_rejected++;
    }
    if(n==32 && packet[0]==0x80 && packet[1]==0xd2){
        packet[1]=0xd3;memcpy(packet+8,packet+24,8);timestamp(packet+16);timestamp(packet+24);
        (void)sendto(m->sockets[2],packet,32,MSG_NOSIGNAL,(struct sockaddr *)&peer,length);
    }
    if(now()-m->timing_sent>=1){
        struct sockaddr_in6 local={0};length=sizeof(local);
        if(getsockname(m->sockets[2],(struct sockaddr *)&local,&length))return -1;
        peer.sin6_family=AF_INET6;peer.sin6_scope_id=local.sin6_scope_id;peer.sin6_port=htons(m->sender_timing_port);
        pc_linklocal(m->peer,peer.sin6_addr.s6_addr);
        memset(packet,0,32);packet[0]=0x80;packet[1]=0xd2;packet[3]=7;timestamp(packet+24);
        uint64_t sent_ns=monotonic_ns();
        ssize_t sent=sendto(m->sockets[2],packet,32,MSG_NOSIGNAL,(struct sockaddr *)&peer,sizeof(peer));
        if(sent==32){m->timing_token=be64(packet+24);m->timing_sent_ns=sent_ns;m->timing_pending=1;}
        if(sent<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return -1;
        m->timing_sent=now();
    }
    return 0;
}
static int media_reject(const struct pc_media *m,const char *stage,int code){
    fprintf(stderr,"native media rejected: stage=%s code=%d packets=%u type=%u type_flags=%u payload=%u header_bytes=%zu payload_bytes=%zu cipher_bytes=%llu nal_length_bytes=%u\n",stage,code,m->packets,m->packet.type,m->packet.type_flags,m->packet.payload_size,m->header_n,m->payload_n,(unsigned long long)m->cipher.bytes,m->config.length_bytes);
    return -1;
}
/* Nonblocking bounded reads: one completed mirror packet per radio step. */
static int receive_part(int fd,uint8_t *out,size_t wanted,size_t *have){
    if(*have==wanted)return 1;
    ssize_t n=recv(fd,out+*have,wanted-*have,0);
    if(n<0)return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 0 : -1;
    if(!n)return -1;
    *have+=(size_t)n;return *have==wanted;
}
int pc_media_step(struct pc_media *m){
    if(!m || !m->phase)return 0;
    if(timing(m) || accept_one(m->sockets[1],&m->event_client))return -1;
    if(m->audio.output){
        for(unsigned port=3;port<5;port++)for(unsigned i=0;i<8;i++){
            uint8_t packet[1501];ssize_t n=recv(m->sockets[port],packet,sizeof(packet),0);
            if(n<0){if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)break;return -1;}
            if(n>1500)continue;
            if(port==3)(void)pc_audio_ingress(&m->audio,packet,(size_t)n);
            else if(n>=16 && (packet[1]&127)==86)(void)pc_audio_ingress(&m->audio,packet+4,(size_t)n-4);
            else if(n==20 && (packet[1]&127)==84)(void)pc_audio_sync(&m->audio,packet,(size_t)n);
        }
        if(pc_audio_step(&m->audio)!=PC_OK)return -1;
    }
    if(m->event_client>=0){uint8_t discard[1024];ssize_t n=recv(m->event_client,discard,sizeof(discard),0);if(!n){close(m->event_client);m->event_client=-1;}}
    if(m->phase<2)return 0;
    if(pc_video_output_step(m->output) || accept_one(m->sockets[0],&m->video_client))return -1;
    if(m->video_client<0)return 0;
    int r=receive_part(m->video_client,m->header,128,&m->header_n);if(r<=0)return r;
    if(!m->payload_n){int parsed=pc_mirror_header_parse(m->header,128,&m->packet);if(parsed!=PC_OK)return media_reject(m,"header",parsed);}
    r=receive_part(m->video_client,m->payload,m->packet.payload_size,&m->payload_n);if(r<=0)return r;
    if(m->packets>=m->packet_limit || m->byte_limit<128+m->packet.payload_size || m->bytes>m->byte_limit-128-m->packet.payload_size)return -1;
    size_t size=m->pending_size;
    if(!size){
    if(m->packet.type==0){
        uint64_t at=monotonic_ns(),mapped;
        if(!pc_clock_local(&m->clock,pc_clock_video_ntp(m->packet.ntp),at,&mapped)){
            int64_t age=at>=mapped ? (int64_t)(at-mapped) : -(int64_t)(mapped-at);
            if(!m->video_clock_samples || age<m->video_age_min_ns)m->video_age_min_ns=age;
            if(!m->video_clock_samples || age>m->video_age_max_ns)m->video_age_max_ns=age;
            m->video_clock_samples++;age_record(m,age);
            mapped=smooth_mapping(m,pc_clock_video_ntp(m->packet.ntp),mapped);
            m->video_align_ns=next_video_align(m->video_align_ns,m->audio.output ? video_align_target_ns() : 0);
            if(m->playout.clock && pc_playout_pts(&m->playout,mapped+m->video_align_ns,&m->pending_pts))return media_reject(m,"presentation_time",PC_INVALID);
            m->clock_wait_since_ns=0;
        }else{
            if(m->playout.clock){
                if(!m->clock_wait_since_ns)m->clock_wait_since_ns=at;
                if(at-m->clock_wait_since_ns<=UINT64_C(2000000000))return 0; /* Keep the reference picture intact while clock sync acquires. */
                /* No usable clock: a late picture beats ending the session. */
                if(pc_playout_pts(&m->playout,at,&m->pending_pts))return media_reject(m,"presentation_time",PC_INVALID);
            }
            m->video_clock_unmapped++;
        }
        int decoded=pc_mirror_cipher_update(&m->cipher,m->payload,m->payload_n,m->payload,PC_MIRROR_MAX_PAYLOAD);
        if(decoded!=PC_OK)return media_reject(m,"cipher",decoded);
        decoded=pc_h264_access_unit(&m->config,m->payload,m->payload_n,m->annex,PC_MIRROR_MAX_PAYLOAD+512,&size);
        if(decoded!=PC_OK)return media_reject(m,"access_unit",decoded);
    }else if(m->packet.type==1){
        int configured=pc_h264_config_decode(m->payload,m->payload_n,&m->config,m->annex,PC_MIRROR_MAX_PAYLOAD+512,&size);
        if(configured!=PC_OK)return media_reject(m,"config",configured);
    }
    }
    if(size){int pushed=pc_video_output_push_at(m->output,m->annex,size,m->packet.type==1,m->playout.clock && m->packet.type==0 ? m->pending_pts : UINT64_MAX);if(pushed<0)return -1;if(pushed>0){m->pending_size=size;return 0;}}
    m->packets++;m->bytes+=128+m->payload_n;
    if(m->packet.type==0){
        uint64_t at=monotonic_ns();
        if(!m->video_packets)m->first_video_ns=at;
        m->last_video_ns=at;m->video_packets++;
    }
    if(m->packet.type==1)m->configs++;
    if(m->packets==1 || m->packets%30==0){
        unsigned frames,width,height;pc_video_output_stats(m->output,&frames,&width,&height);
        printf("{\"event\":\"native_media_progress\",\"packets\":%u,\"configs\":%u,\"video_packets\":%u,\"decoded_frames\":%u,\"width\":%u,\"height\":%u}\n",m->packets,m->configs,m->video_packets,frames,width,height);
    }
    m->header_n=m->payload_n=m->pending_size=0;return 0;
}

/* Reusable same-process HDMI output for the original PiCast mirror parser. */
#include "picast_video_output.h"
#include "picast_playout.h"
#include "picast_crop.h"
#include "picast_overlay.h"
#include <gst/app/gstappsrc.h>
#include <gst/video/video.h>
#include <gst/base/gstbasesink.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Crop state lives in the decoder thread only (pad probe), except the counters. */
struct crop { int enabled; gint64 next; unsigned width,height; struct pc_crop_tracker tracker; };
/* Smoothness as seen on screen: each picture's spacing on screen against its
 * spacing at the sender. Kept in the sink's streaming thread. */
struct pacing { GstClockTime last_shown,last_pts; };
struct output { GstElement *pipeline,*sink; GstAppSrc *input; GstBus *bus; struct pacing pacing; atomic_uint frames,width,height,crop_changes,crop_w,crop_h,paced,uneven,stalls,worst_ms; unsigned timed,headless,overlay_tried; struct pc_overlay *overlay; struct crop crop; };
void pc_video_output_prepare(void){gst_init(NULL,NULL);}
/* Pictures are shown at their due time, sharing the sound's delay, so a radio hiccup
 * up to the buffer's size never reaches the screen (r227, r229). PICAST_VIDEO_NOW
 * shows each picture once decoded instead, for the lowest delay. */
int pc_video_timed(void){return getenv("PICAST_VIDEO_NOW")==NULL;}
/* About every 0.4 s one decoded picture is checked for black bars; the tracker in
 * crop.c decides slowly to crop and quickly to show everything again. */
#define PC_CROP_SAMPLE_US 400000
static void crop_sample(struct output *o,GstBuffer *buffer){
    struct crop *k=&o->crop;
    gint64 now=g_get_monotonic_time();
    if(now<k->next || !k->width || !k->height)return;
    k->next=now+PC_CROP_SAMPLE_US;
    GstVideoMeta *meta=gst_buffer_get_video_meta(buffer);
    gsize offset=meta ? meta->offset[0] : 0;size_t stride=meta ? (size_t)meta->stride[0] : k->width;
    GstMapInfo map;
    if(!gst_buffer_map(buffer,&map,GST_MAP_READ))return;
    struct pc_crop_box content;int found=-1;
    if(stride>=k->width && offset+stride*(k->height-1)+k->width<=map.size){
        if(!pc_crop_is_full(&k->tracker) && pc_crop_bars_lit(map.data+offset,stride,k->width,k->height,&k->tracker.shown)){
            content=(struct pc_crop_box){0,0,k->width,k->height};found=0;
        }else found=pc_crop_detect(map.data+offset,stride,k->width,k->height,&content);
    }
    gst_buffer_unmap(buffer,&map);
    if(pc_crop_update(&k->tracker,found ? NULL : &content)){
        atomic_fetch_add(&o->crop_changes,1);
        atomic_store(&o->crop_w,k->tracker.shown.w);atomic_store(&o->crop_h,k->tracker.shown.h);
        fprintf(stderr,"video crop: %u,%u %ux%u of %ux%u\n",k->tracker.shown.x,k->tracker.shown.y,k->tracker.shown.w,k->tracker.shown.h,k->width,k->height);
    }
}
static GstPadProbeReturn decoded(GstPad *pad,GstPadProbeInfo *info,gpointer ctx) {
    (void)pad;struct output *o=ctx;
    if(GST_PAD_PROBE_INFO_TYPE(info)&GST_PAD_PROBE_TYPE_BUFFER){
        atomic_fetch_add(&o->frames,1);
        if(o->crop.enabled){
            GstBuffer *buffer=GST_PAD_PROBE_INFO_BUFFER(info);
            crop_sample(o,buffer);
            /* The display scales the cropped area to fill the screen, keeping its shape. */
            if(!pc_crop_is_full(&o->crop.tracker)){
                buffer=gst_buffer_make_writable(buffer);
                GstVideoCropMeta *crop=gst_buffer_get_video_crop_meta(buffer);
                if(!crop)crop=gst_buffer_add_video_crop_meta(buffer);
                if(crop){crop->x=o->crop.tracker.shown.x;crop->y=o->crop.tracker.shown.y;crop->width=o->crop.tracker.shown.w;crop->height=o->crop.tracker.shown.h;}
                GST_PAD_PROBE_INFO_DATA(info)=buffer;
            }
        }
    }
    if(GST_PAD_PROBE_INFO_TYPE(info)&GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM){
        GstEvent *event=GST_PAD_PROBE_INFO_EVENT(info);
        if(GST_EVENT_TYPE(event)==GST_EVENT_CAPS){
            GstCaps *caps;GstVideoInfo v;gst_event_parse_caps(event,&caps);
            if(gst_video_info_from_caps(&v,caps)){
                atomic_store(&o->width,GST_VIDEO_INFO_WIDTH(&v));atomic_store(&o->height,GST_VIDEO_INFO_HEIGHT(&v));
                /* A new picture size (rotation, another app) starts the decision over. */
                if(o->crop.width!=(unsigned)GST_VIDEO_INFO_WIDTH(&v) || o->crop.height!=(unsigned)GST_VIDEO_INFO_HEIGHT(&v)){
                    o->crop.width=GST_VIDEO_INFO_WIDTH(&v);o->crop.height=GST_VIDEO_INFO_HEIGHT(&v);
                    pc_crop_reset(&o->crop.tracker,o->crop.width,o->crop.height);o->crop.next=0;
                }
            }
        }
    }
    return GST_PAD_PROBE_OK;
}
/* A picture shows when it reaches the display, or at its due time when pictures are
 * timed and it is early. Spacing off by more than two refreshes reads as a jerk,
 * by more than 100 ms as a visible stall. */
static GstPadProbeReturn arriving(GstPad *pad,GstPadProbeInfo *info,gpointer ctx){
    struct output *o=ctx;GstBuffer *buffer=GST_PAD_PROBE_INFO_BUFFER(info);
    GstClockTime pts=GST_BUFFER_PTS(buffer);
    GstClock *clock=gst_element_get_clock(o->sink);
    if(!clock || !GST_CLOCK_TIME_IS_VALID(pts)){if(clock)gst_object_unref(clock);return GST_PAD_PROBE_OK;}
    GstClockTime now=gst_clock_get_time(clock),shown=now;gst_object_unref(clock);
    if(o->timed && pc_video_timed()){
        GstEvent *seg=gst_pad_get_sticky_event(pad,GST_EVENT_SEGMENT,0);
        if(seg){
            const GstSegment *segment;gst_event_parse_segment(seg,&segment);
            GstClockTime running=gst_segment_to_running_time(segment,GST_FORMAT_TIME,pts);
            if(GST_CLOCK_TIME_IS_VALID(running)){GstClockTime due=gst_element_get_base_time(o->sink)+running;if(due>shown)shown=due;}
            gst_event_unref(seg);
        }
    }
    struct pacing *p=&o->pacing;
    if(p->last_shown && pts>p->last_pts && pts-p->last_pts<GST_SECOND){
        gint64 jitter=(gint64)(shown-p->last_shown)-(gint64)(pts-p->last_pts);
        if(jitter<0)jitter=-jitter;
        atomic_fetch_add(&o->paced,1);
        if(jitter>34*GST_MSECOND)atomic_fetch_add(&o->uneven,1);
        if(jitter>100*GST_MSECOND)atomic_fetch_add(&o->stalls,1);
        unsigned ms=(unsigned)(jitter/GST_MSECOND);
        if(ms>atomic_load(&o->worst_ms))atomic_store(&o->worst_ms,ms);
    }
    p->last_shown=shown;p->last_pts=pts;
    return GST_PAD_PROBE_OK;
}
void pc_video_output_pacing_stats(void *state,unsigned *paced,unsigned *uneven,unsigned *stalls,unsigned *worst_ms){
    struct output *o=state;
    *paced=o ? atomic_load(&o->paced) : 0;*uneven=o ? atomic_load(&o->uneven) : 0;*stalls=o ? atomic_load(&o->stalls) : 0;*worst_ms=o ? atomic_load(&o->worst_ms) : 0;
}
void pc_video_output_close(void *state){
    struct output *o=state;if(!o)return;
    pc_overlay_stop(o->overlay);  /* uses the sink's DRM connection, so first */
    if(o->pipeline)gst_element_set_state(o->pipeline,GST_STATE_NULL);
    if(o->input)gst_object_unref(o->input);
    if(o->bus)gst_object_unref(o->bus);
    if(o->sink)gst_object_unref(o->sink);
    if(o->pipeline)gst_object_unref(o->pipeline);
    free(o);
}
/* iOS tags its stream 1:3:7:1 (full range, sRGB transfer). v4l2h264dec does not
 * list that colorimetry and refuses the whole stream, though decoding does not
 * depend on it, so hand the decoder a value it accepts. */
#define PC_DECODER_CAPS "capssetter caps=\"video/x-h264,colorimetry=(string)bt709\""
void *pc_video_output_open(int headless){return pc_video_output_open_timed(headless,NULL);}
void *pc_video_output_open_timed(int headless,const struct pc_playout *playout){
    gint64 started=g_get_monotonic_time();gst_init(NULL,NULL);gint64 initialized=g_get_monotonic_time();struct output *o=calloc(1,sizeof(*o));if(!o)return NULL;
    atomic_init(&o->frames,0);atomic_init(&o->width,0);atomic_init(&o->height,0);
    atomic_init(&o->crop_changes,0);atomic_init(&o->crop_w,0);atomic_init(&o->crop_h,0);
    atomic_init(&o->paced,0);atomic_init(&o->uneven,0);atomic_init(&o->stalls,0);atomic_init(&o->worst_ms,0);
    GError *error=NULL;o->headless=(unsigned)headless;
    /* Black-bar removal: on unless PICAST_NO_CROP is set; also measured headless. */
    o->crop.enabled=!getenv("PICAST_NO_CROP");
    o->pipeline=gst_parse_launch(headless ?
        "appsrc name=input format=time is-live=true do-timestamp=true block=false ! h264parse ! " PC_DECODER_CAPS " ! v4l2h264dec name=decode ! fakesink name=display sync=false" :
        "appsrc name=input format=time is-live=true do-timestamp=true block=false ! h264parse ! " PC_DECODER_CAPS " ! v4l2h264dec name=decode ! kmssink name=display driver-name=vc4 sync=false",&error);
    if(!o->pipeline || error){g_clear_error(&error);pc_video_output_close(o);return NULL;}
    o->sink=gst_bin_get_by_name(GST_BIN(o->pipeline),"display");
    if(!o->sink){pc_video_output_close(o);return NULL;}
    if(playout){
        if(pc_playout_attach(playout,o->pipeline)){pc_video_output_close(o);return NULL;}
        /* Show late pictures at once. Over AWDL, arrival jitter regularly exceeds
         * the playout delay; dropping then froze the mirrored screen (r164 decoded
         * 745 of 1280 frames). qos=FALSE keeps the decoder from dropping them too. */
        /* Pictures wait for their due time (pc_video_timed); until r226 each was
         * shown once decoded, for the lowest delay (r183, r184), which
         * PICAST_VIDEO_NOW still does. */
        g_object_set(o->sink,"sync",pc_video_timed() ? TRUE : FALSE,"max-lateness",(gint64)-1,"qos",FALSE,NULL);
        o->timed=1;
    }
    /* kmssink's own vblank wait, on top of the page flip, halves a 60 Hz output: 300
     * pictures took 10.5 s with it and 5.4 s without, whatever their size, and a 60/s
     * sender built up seconds of delay (r200). PICAST_KMS_VSYNC restores the wait. */
    if(!headless && !getenv("PICAST_KMS_VSYNC"))g_object_set(o->sink,"skip-vsync",TRUE,NULL);
    /* iOS declares full range (1:3:7:1), the display plane assumes limited by default. */
    const char *range=getenv("PICAST_COLOR_RANGE");
    if(!headless && range && !strcmp(range,"full")){
        GstStructure *plane=gst_structure_from_string("plane,COLOR_RANGE=(int)1",NULL);
        if(plane){g_object_set(o->sink,"plane-properties",plane,NULL);gst_structure_free(plane);}
    }
    o->input=GST_APP_SRC(gst_bin_get_by_name(GST_BIN(o->pipeline),"input"));
    GstElement *decode=gst_bin_get_by_name(GST_BIN(o->pipeline),"decode");
    if(!o->input || !decode){if(decode)gst_object_unref(decode);pc_video_output_close(o);return NULL;}
    if(o->timed)g_object_set(o->input,"do-timestamp",FALSE,NULL);
    GstPad *pad=gst_element_get_static_pad(decode,"src");
    gst_pad_add_probe(pad,GST_PAD_PROBE_TYPE_BUFFER|GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM,decoded,o,NULL);
    gst_object_unref(pad);gst_object_unref(decode);
    GstPad *sink_pad=gst_element_get_static_pad(o->sink,"sink");
    if(sink_pad){gst_pad_add_probe(sink_pad,GST_PAD_PROBE_TYPE_BUFFER,arriving,o,NULL);gst_object_unref(sink_pad);}
    GstCaps *caps=gst_caps_from_string("video/x-h264,stream-format=(string)byte-stream,alignment=(string)au");
    gst_app_src_set_caps(o->input,caps);gst_caps_unref(caps);
    gst_app_src_set_max_bytes(o->input,2U*1024U*1024U);
    o->bus=gst_element_get_bus(o->pipeline);
    gint64 configured=g_get_monotonic_time();
    if(gst_element_set_state(o->pipeline,GST_STATE_PLAYING)==GST_STATE_CHANGE_FAILURE){pc_video_output_close(o);return NULL;}
    fprintf(stderr,"video startup: init_us=%lld graph_us=%lld state_us=%lld\n",(long long)(initialized-started),(long long)(configured-initialized),(long long)(g_get_monotonic_time()-configured));
    return o;
}
int pc_video_output_step(void *state){
    struct output *o=state;if(!o)return -1;
    /* The battery corner above the picture, once the sink has shown its first one. */
    if(!o->headless && !o->overlay_tried && atomic_load(&o->frames)){
        gint fd=-1,plane=-1;o->overlay_tried=1;
        g_object_get(o->sink,"fd",&fd,"plane-id",&plane,NULL);
        if(!getenv("PICAST_NO_OVERLAY") && fd>=0 && plane>0)o->overlay=pc_overlay_start(fd,(unsigned)plane);
    }
    GstMessage *m=gst_bus_pop_filtered(o->bus,GST_MESSAGE_ERROR);
    if(!m)return 0;
    GError *error=NULL;gchar *detail=NULL;gst_message_parse_error(m,&error,&detail);
    fprintf(stderr,"native video output: %s\n",error ? error->message : "unavailable");
    g_clear_error(&error);g_free(detail);gst_message_unref(m);return -1;
}
int pc_video_output_push(void *state,const uint8_t *data,size_t n,int config){
    return pc_video_output_push_at(state,data,n,config,GST_CLOCK_TIME_NONE);
}
int pc_video_output_push_at(void *state,const uint8_t *data,size_t n,int config,uint64_t pts){
    struct output *o=state;if(!o || !data || !n || n>1024U*1024U+512 || pc_video_output_step(o))return -1;
    if(o->timed && !config && pts==GST_CLOCK_TIME_NONE)return -1;
    if(gst_app_src_get_current_level_bytes(o->input)>2U*1024U*1024U)return 1;
    GstBuffer *buffer=gst_buffer_new_allocate(NULL,n,NULL);if(!buffer)return -1;
    if(gst_buffer_fill(buffer,0,data,n)!=n){gst_buffer_unref(buffer);return -1;}
    GST_BUFFER_PTS(buffer)=pts;GST_BUFFER_DTS(buffer)=GST_CLOCK_TIME_NONE;
    if(config)GST_BUFFER_FLAG_SET(buffer,GST_BUFFER_FLAG_HEADER);
    return gst_app_src_push_buffer(o->input,buffer)==GST_FLOW_OK ? 0 : -1;
}
void pc_video_output_stats(void *state,unsigned *frames,unsigned *width,unsigned *height){
    struct output *o=state;*frames=o ? atomic_load(&o->frames) : 0;*width=o ? atomic_load(&o->width) : 0;*height=o ? atomic_load(&o->height) : 0;
}
void pc_video_output_crop_stats(void *state,unsigned *changes,unsigned *width,unsigned *height){
    struct output *o=state;*changes=o ? atomic_load(&o->crop_changes) : 0;*width=o ? atomic_load(&o->crop_w) : 0;*height=o ? atomic_load(&o->crop_h) : 0;
}
void pc_video_output_delivery_stats(void *state,uint64_t *rendered,uint64_t *dropped){
    struct output *o=state;*rendered=*dropped=0;
    if(!o || !o->sink)return;
    GstStructure *stats=gst_base_sink_get_stats(GST_BASE_SINK(o->sink));
    if(stats){guint64 r=0,d=0;gst_structure_get_uint64(stats,"rendered",&r);gst_structure_get_uint64(stats,"dropped",&d);*rendered=r;*dropped=d;gst_structure_free(stats);}
}

int pc_video_output_end(void *state){
    struct output *o=state;return o && gst_app_src_end_of_stream(o->input)==GST_FLOW_OK ? 0 : -1;
}

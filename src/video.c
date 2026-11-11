/* Optional standard-GStreamer output for our own plaintext mirror parser.
 * No listener, pairing, decryption or claim of native AirPlay interoperability. */
#include "picast_mirror.h"
#include <gst/app/gstappsrc.h>
#include <gst/video/video.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static atomic_uint frames, width, height;
static double now(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;
}
static void stop(int sig) { (void)sig;interrupted=1; }
static GstPadProbeReturn decoded(GstPad *pad,GstPadProbeInfo *info,gpointer ctx) {
    (void)pad;(void)ctx;
    if (GST_PAD_PROBE_INFO_TYPE(info)&GST_PAD_PROBE_TYPE_BUFFER) atomic_fetch_add(&frames,1);
    if (GST_PAD_PROBE_INFO_TYPE(info)&GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM) {
        GstEvent *event=GST_PAD_PROBE_INFO_EVENT(info);
        if (GST_EVENT_TYPE(event)==GST_EVENT_CAPS) {
            GstCaps *caps;GstVideoInfo video;gst_event_parse_caps(event,&caps);
            if (gst_video_info_from_caps(&video,caps)) {
                atomic_store(&width,GST_VIDEO_INFO_WIDTH(&video));atomic_store(&height,GST_VIDEO_INFO_HEIGHT(&video));
            }
        }
    }
    return GST_PAD_PROBE_OK;
}
static int bus_error(GstBus *bus) {
    GstMessage *message=gst_bus_pop_filtered(bus,GST_MESSAGE_ERROR);
    if (!message) return 0;
    GError *error=NULL;gchar *detail=NULL;gst_message_parse_error(message,&error,&detail);
    fprintf(stderr,"video decoder/output: %s\n",error ? error->message : "unknown error");
    g_clear_error(&error);g_free(detail);gst_message_unref(message);return 1;
}
/* Return 1 on complete read, 0 on clean EOF, -1 on truncation/deadline. */
static int read_exact(uint8_t *out,size_t wanted,double deadline,GstBus *bus) {
    size_t have=0;
    while (have<wanted && !interrupted && now()<deadline) {
        if (bus_error(bus)) return -1;
        struct pollfd fd={STDIN_FILENO,POLLIN,0};int ready=poll(&fd,1,100);
        if (ready<0) { if (errno==EINTR) continue;return -1; }
        if (!ready) continue;
        ssize_t n=read(STDIN_FILENO,out+have,wanted-have);
        if (n==0) return have ? -1 : 0;
        if (n<0) { if (errno==EINTR || errno==EAGAIN) continue;return -1; }
        have+=(size_t)n;
    }
    return have==wanted ? 1 : -1;
}
int main(int argc,char **argv) {
    int headless=argc==3 && !strcmp(argv[2],"--headless");
    if ((argc!=2 && !headless) || strcmp(argv[1],"--clear-input")) {
        fputs("Usage: picast-video --clear-input [--headless] < framed-plaintext.bin\n",stderr);return 2;
    }
    signal(SIGINT,stop);signal(SIGTERM,stop);gst_init(NULL,NULL);
    GError *error=NULL;
    const char *graph=headless ? "appsrc name=input format=time is-live=false block=false ! h264parse ! v4l2h264dec name=decode ! fakesink sync=false" :
        "appsrc name=input format=time is-live=false block=false ! h264parse ! v4l2h264dec name=decode ! kmssink driver-name=vc4 sync=true";
    GstElement *pipeline=gst_parse_launch(graph,&error);
    if (!pipeline || error) {
        fprintf(stderr,"video pipeline: %s\n",error ? error->message : "unavailable");
        g_clear_error(&error);if (pipeline) gst_object_unref(pipeline);return 1;
    }
    GstAppSrc *input=GST_APP_SRC(gst_bin_get_by_name(GST_BIN(pipeline),"input"));
    GstElement *decode=gst_bin_get_by_name(GST_BIN(pipeline),"decode");
    GstPad *pad=gst_element_get_static_pad(decode,"src");
    gst_pad_add_probe(pad,GST_PAD_PROBE_TYPE_BUFFER|GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM,decoded,NULL,NULL);
    gst_object_unref(pad);gst_object_unref(decode);
    GstCaps *caps=gst_caps_from_string("video/x-h264, stream-format=(string)byte-stream, alignment=(string)au");
    gst_app_src_set_caps(input,caps);gst_caps_unref(caps);
    GstBus *bus=gst_element_get_bus(pipeline);
    int result=1,clean_eof=0;unsigned packets=0,video_packets=0,configs=0;
    uint64_t first_ntp=0;int have_ntp=0;size_t total=0;
    double deadline=now()+60;
    uint8_t *payload=malloc(PC_MIRROR_MAX_PAYLOAD),*annex=malloc(PC_MIRROR_MAX_PAYLOAD+4*PC_H264_MAX_NALS);
    struct pc_h264_config config={0};
    if (!payload || !annex || gst_element_set_state(pipeline,GST_STATE_PLAYING)==GST_STATE_CHANGE_FAILURE) goto cleanup;
    while (packets<2048 && total<32U*1024U*1024U && !interrupted && now()<deadline) {
        uint8_t raw[PC_MIRROR_HEADER_SIZE];struct pc_mirror_header h;
        int got=read_exact(raw,sizeof(raw),deadline,bus);
        if (!got) { clean_eof=1;break; }
        if (got<0 || pc_mirror_header_parse(raw,sizeof(raw),&h)!=PC_OK) goto cleanup;
        if (total>32U*1024U*1024U-sizeof(raw) || h.payload_size>32U*1024U*1024U-sizeof(raw)-total) goto cleanup;
        if (h.payload_size && read_exact(payload,h.payload_size,deadline,bus)!=1) goto cleanup;
        total+=sizeof(raw)+h.payload_size;packets++;
        if (h.type==2 || h.type==5) continue;
        size_t size=0;
        int rc=h.type==1 ? pc_h264_config_decode(payload,h.payload_size,&config,annex,PC_MIRROR_MAX_PAYLOAD+4*PC_H264_MAX_NALS,&size) :
            pc_h264_access_unit(&config,payload,h.payload_size,annex,PC_MIRROR_MAX_PAYLOAD+4*PC_H264_MAX_NALS,&size);
        if (rc!=PC_OK) { fprintf(stderr,"video payload rejected: %d\n",rc);goto cleanup; }
        GstClockTime pts=GST_CLOCK_TIME_NONE;
        if (h.type==0) {
            if (!have_ntp) { first_ntp=h.ntp;have_ntp=1; }
            if (h.ntp<first_ntp || ((h.ntp-first_ntp)>>32)>60) goto cleanup;
            uint64_t delta=h.ntp-first_ntp;
            pts=(delta>>32)*GST_SECOND+((delta&UINT64_C(0xffffffff))*GST_SECOND>>32);
            video_packets++;
        } else configs++;
        while (gst_app_src_get_current_level_bytes(input)>2U*1024U*1024U) {
            if (interrupted || now()>=deadline || bus_error(bus)) goto cleanup;
            struct timespec pause={0,10000000};nanosleep(&pause,NULL);
        }
        GstBuffer *buffer=gst_buffer_new_allocate(NULL,size,NULL);
        if (!buffer || gst_buffer_fill(buffer,0,annex,size)!=size) { if (buffer) gst_buffer_unref(buffer);goto cleanup; }
        GST_BUFFER_PTS(buffer)=pts;GST_BUFFER_DTS(buffer)=GST_CLOCK_TIME_NONE;
        if (h.type==1) GST_BUFFER_FLAG_SET(buffer,GST_BUFFER_FLAG_HEADER);
        if (gst_app_src_push_buffer(input,buffer)!=GST_FLOW_OK) goto cleanup;
    }
    if (!clean_eof || !video_packets || gst_app_src_end_of_stream(input)!=GST_FLOW_OK) goto cleanup;
    while (!interrupted && now()<deadline) {
        GstMessage *message=gst_bus_timed_pop_filtered(bus,100*GST_MSECOND,GST_MESSAGE_EOS|GST_MESSAGE_ERROR);
        if (!message) continue;
        if (GST_MESSAGE_TYPE(message)==GST_MESSAGE_EOS) result=atomic_load(&frames)>0 ? 0 : 1;
        else {
            GError *failure=NULL;gchar *detail=NULL;gst_message_parse_error(message,&failure,&detail);
            fprintf(stderr,"video pipeline: %s\n",failure ? failure->message : "unknown error");
            g_clear_error(&failure);g_free(detail);
        }
        gst_message_unref(message);break;
    }
cleanup:
    gst_element_set_state(pipeline,GST_STATE_NULL);
    printf("{\"event\":\"video_output_finished\",\"success\":%s,\"decoder\":\"v4l2h264dec\",\"decoded_frames\":%u,\"width\":%u,\"height\":%u,\"packets\":%u,\"video_packets\":%u,\"configs\":%u,\"headless\":%s,\"native_airplay_verified\":false}\n",
           result==0 ? "true":"false",atomic_load(&frames),atomic_load(&width),atomic_load(&height),packets,video_packets,configs,headless ? "true":"false");
    free(payload);free(annex);gst_object_unref(input);gst_object_unref(bus);gst_object_unref(pipeline);
    return result;
}

#include "picast_playout.h"
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <stdatomic.h>
#include <assert.h>
#include <stdio.h>
struct rendered {GstClock *clock;atomic_uint_fast64_t at;};
static void rendered(GstElement *sink,GstBuffer *buffer,GstPad *pad,gpointer state) {
    (void)sink;(void)buffer;(void)pad;struct rendered *r=state;
    atomic_store(&r->at,gst_clock_get_time(r->clock));
}
static void shared_presentation_test(int asynchronous) {
    struct pc_playout p={0};assert(!pc_playout_open(&p,120*GST_MSECOND));
    GError *error=NULL;
    const char *graph=asynchronous ?
        "appsrc name=input is-live=true format=time ! fakesink name=sink sync=true async=true signal-handoffs=true" :
        "appsrc name=input is-live=true format=time ! fakesink name=sink sync=true async=false signal-handoffs=true";
    GstElement *v=gst_parse_launch(graph,&error);assert(v && !error);
    GstElement *a=gst_parse_launch(graph,&error);assert(a && !error);
    assert(!pc_playout_attach(&p,v) && !pc_playout_attach(&p,a));
    struct rendered observations[2]={{.clock=p.clock},{.clock=p.clock}};
    GstElement *pipelines[2]={v,a};
    for(unsigned i=0;i<2;i++) {
        atomic_init(&observations[i].at,0);
        GstElement *sink=gst_bin_get_by_name(GST_BIN(pipelines[i]),"sink");
        g_signal_connect(sink,"handoff",G_CALLBACK(rendered),&observations[i]);gst_object_unref(sink);
        assert(gst_element_set_state(pipelines[i],GST_STATE_PLAYING)!=GST_STATE_CHANGE_FAILURE);
        if(!i)g_usleep(75000); /* Deliberately stagger graph startup. */
    }
    uint64_t first_pts=gst_clock_get_time(p.clock)-p.base_clock_ns+500*GST_MSECOND;
    for(unsigned i=0;i<2;i++) {
        GstAppSrc *source=GST_APP_SRC(gst_bin_get_by_name(GST_BIN(pipelines[i]),"input"));
        GstBuffer *b=gst_buffer_new_allocate(NULL,1,NULL);assert(b);
        GST_BUFFER_PTS(b)=first_pts;GST_BUFFER_DURATION(b)=10*GST_MSECOND;
        assert(gst_app_src_push_buffer(source,b)==GST_FLOW_OK);gst_object_unref(source);
    }
    gint64 deadline=g_get_monotonic_time()+2000000;
    while((!atomic_load(&observations[0].at) || !atomic_load(&observations[1].at)) && g_get_monotonic_time()<deadline)g_usleep(1000);
    uint64_t x=atomic_load(&observations[0].at),y=atomic_load(&observations[1].at),due=p.base_clock_ns+first_pts+p.delay_ns;
    assert(x>=due && y>=due && x-due<100*GST_MSECOND && y-due<100*GST_MSECOND);
    uint64_t difference=x>y ? x-y : y-x;assert(difference<40*GST_MSECOND);
    printf("shared presentation with75ms graph-start offset: asynchronous=%d measured_fake_sink_skew_ns=%llu\n",asynchronous,(unsigned long long)difference);
    gst_element_set_state(v,GST_STATE_NULL);gst_element_set_state(a,GST_STATE_NULL);
    gst_object_unref(v);gst_object_unref(a);pc_playout_close(&p);
}
int main(void) {
    struct pc_playout p={0};uint64_t pts=0;
    assert(pc_playout_open(&p,501*GST_MSECOND)<0);
    assert(!pc_playout_open(&p,120*GST_MSECOND));
    assert(pc_playout_open(&p,0)<0);
    GstElement *video=gst_pipeline_new("video"),*audio=gst_pipeline_new("audio");
    assert(!pc_playout_attach(&p,video) && !pc_playout_attach(&p,audio));
    assert(gst_element_get_base_time(video)==p.base_clock_ns);
    assert(gst_element_get_base_time(audio)==p.base_clock_ns);
    assert(gst_pipeline_get_latency(GST_PIPELINE(audio))==p.delay_ns);
    assert(gst_pipeline_get_latency(GST_PIPELINE(video))==p.delay_ns);
    GstClock *a=gst_pipeline_get_pipeline_clock(GST_PIPELINE(audio));
    GstClock *v=gst_pipeline_get_pipeline_clock(GST_PIPELINE(video));
    assert(a==v && a==p.clock);gst_object_unref(a);gst_object_unref(v);
    assert(!pc_playout_pts(&p,p.base_local_ns,&pts) && pts==0);
    assert(!pc_playout_pts(&p,p.base_local_ns+GST_SECOND,&pts) && pts==GST_SECOND);
    assert(pc_playout_pts(&p,p.base_local_ns-100*GST_MSECOND,&pts)<0);
    assert(pc_playout_pts(&p,p.base_local_ns-121*GST_MSECOND,&pts)<0);
    uint64_t base=p.base_local_ns;p.base_local_ns=0;
    assert(pc_playout_pts(&p,UINT64_MAX,&pts)<0);p.base_local_ns=base;
    assert(gst_element_set_state(audio,GST_STATE_PLAYING)!=GST_STATE_CHANGE_FAILURE);
    assert(pc_playout_attach(&p,audio)<0);
    gst_element_set_state(audio,GST_STATE_NULL);gst_object_unref(audio);gst_object_unref(video);
    pc_playout_close(&p);assert(!p.clock && pc_playout_pts(&p,0,&pts)<0);pc_playout_close(&p);
    shared_presentation_test(0);shared_presentation_test(1);
    puts("playout: shared clock/base, delayed graph start guard, bounded latency, epoch conversion and cleanup passed");
}

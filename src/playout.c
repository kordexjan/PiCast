#include "picast_playout.h"
#include <gst/gst.h>
#include <string.h>
#include <time.h>
static uint64_t local_time(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;
    return (uint64_t)t.tv_sec*GST_SECOND+(uint64_t)t.tv_nsec;
}
int pc_playout_open(struct pc_playout *p,uint64_t delay) {
    if(!p || p->clock || delay>500*GST_MSECOND)return -1;
    gst_init(NULL,NULL);
    GstClock *clock=gst_system_clock_obtain();
    if(!clock)return -1;
    /* Bracket the clock query to bound conversion error. GstClock epochs
     * are intentionally not assumed to equal CLOCK_MONOTONIC's epoch. */
    uint64_t before=local_time(),at=gst_clock_get_time(clock),after=local_time();
    if(before==UINT64_MAX || after<before || after-before>GST_MSECOND || at==GST_CLOCK_TIME_NONE){gst_object_unref(clock);return -1;}
    uint64_t local=before+(after-before)/2,headroom=GST_SECOND;
    if(headroom>at)headroom=at;
    if(headroom>local)headroom=local;
    /* A past common origin permits initial media timestamps slightly before
     * setup, without negative Gst PTS or adding latency a second time. */
    *p=(struct pc_playout){clock,at-headroom,local-headroom,delay};
    return 0;
}
void pc_playout_close(struct pc_playout *p) {
    if(!p)return;
    if(p->clock)gst_object_unref(p->clock);
    memset(p,0,sizeof(*p));
}
int pc_playout_attach(const struct pc_playout *p,void *pipeline) {
    if(!p || !p->clock || !pipeline || !GST_IS_PIPELINE(pipeline))return -1;
    /* Attach before PLAYING. Automatic base-time selection would otherwise
     * shift audio relative to video when one decoder starts later. */
    GstState state,pending;
    gst_element_get_state(GST_ELEMENT(pipeline),&state,&pending,0);
    if(state>GST_STATE_READY || pending>GST_STATE_READY)return -1;
    gst_pipeline_use_clock(GST_PIPELINE(pipeline),GST_CLOCK(p->clock));
    gst_element_set_start_time(GST_ELEMENT(pipeline),GST_CLOCK_TIME_NONE);
    gst_element_set_base_time(GST_ELEMENT(pipeline),p->base_clock_ns);
    /* Override each graph's automatic latency: ALSA and KMS report different
     * minimum latencies, which would offset equal PTS on a shared clock. */
    gst_pipeline_set_latency(GST_PIPELINE(pipeline),p->delay_ns);
    return 0;
}
int pc_playout_pts(const struct pc_playout *p,uint64_t local,uint64_t *pts) {
    if(!p || !p->clock || !pts)return -1;
    if(local<p->base_local_ns || local==UINT64_MAX)return -1;
    /* Latency is applied once by the pipeline, not also added to PTS. */
    *pts=local-p->base_local_ns;
    return 0;
}

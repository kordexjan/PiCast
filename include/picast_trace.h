#ifndef PICAST_TRACE_H
#define PICAST_TRACE_H
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
/* Keep a valid contiguous PCAP prefix. In a long receiver test, diagnostic
 * saturation stops recording rather than stopping the media connection. */
struct pc_trace {
    FILE *stream;
    size_t limit, bytes, skipped;
    unsigned soft_limit, saturated;
};
int pc_trace_init(struct pc_trace *,FILE *,size_t limit,int soft_limit);
int pc_trace_room(const struct pc_trace *,size_t packet_size);
int pc_trace_write(struct pc_trace *,uint32_t seconds,uint32_t microseconds,const uint8_t *,size_t);
#endif

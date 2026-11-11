#ifndef PICAST_CLOCK_H
#define PICAST_CLOCK_H
#include <stdint.h>
#include <stddef.h>
/* Sender NTP Q32.32 -> receiver monotonic nanoseconds. No wall-clock epoch
 * assumption: audio/video and timing packets must use the same sender clock. */
struct pc_clock_sample { uint64_t remote, local_ns, delay_ns; };
struct pc_clock {
    struct pc_clock_sample samples[8];
    unsigned count, next;
};
int pc_clock_observe(struct pc_clock *, uint64_t sent_ns, uint64_t received_ns,
                     uint64_t remote_receive, uint64_t remote_send);
int pc_clock_local(const struct pc_clock *, uint64_t remote, uint64_t now_ns,
                   uint64_t *local_ns);
/* Only call after validating the datagram's peer address and timing port. */
int pc_clock_reply(struct pc_clock *, uint64_t token, uint64_t sent_ns,
                   uint64_t received_ns, const uint8_t *, size_t);
int pc_clock_rtp(uint32_t rtp, uint32_t anchor_rtp, uint64_t anchor_ntp,
                 unsigned rate, uint64_t *remote_ntp);
/* Classic NTP mirroring omits the 1900->1970 epoch term in VIDEO only.
 * Audio sync anchors and timing replies already contain it. */
uint64_t pc_clock_video_ntp(uint64_t raw_video_time);
#endif

#ifndef PICAST_PLAYOUT_H
#define PICAST_PLAYOUT_H
#include <stdint.h>
/* One clock/base time per session, shared by independent decoder graphs. */
struct pc_playout {
    void *clock;
    uint64_t base_clock_ns, base_local_ns, delay_ns;
};
int pc_playout_open(struct pc_playout *, uint64_t delay_ns);
void pc_playout_close(struct pc_playout *);
int pc_playout_attach(const struct pc_playout *, void *pipeline);
/* local_ns is in CLOCK_MONOTONIC, already mapped from the sender clock. */
int pc_playout_pts(const struct pc_playout *, uint64_t local_ns, uint64_t *pts);
#endif

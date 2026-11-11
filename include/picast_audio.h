#ifndef PICAST_AUDIO_H
#define PICAST_AUDIO_H
#include <stddef.h>
#include <stdint.h>
#define PC_AUDIO_WINDOW 128U
struct pc_clock;
struct pc_playout;
struct pc_audio_slot { uint16_t sequence; uint32_t timestamp; size_t size; uint8_t data[1500]; };
struct pc_audio {
    uint8_t key[16],iv[16];
    struct pc_audio_slot slots[PC_AUDIO_WINDOW];
    uint16_t expected,newest;
    unsigned initialized,have_sequence,received,duplicates,lost,submitted;
    unsigned buffered_dropped,late_dropped;
    uint64_t clock_samples;
    int64_t ingress_age_min_ns,ingress_age_max_ns;
    void *output;
    double volume_db;
    uint64_t sync_ntp;
    uint32_t sync_rtp;
    unsigned sync_valid;
};
int pc_audio_key(struct pc_audio *,const uint8_t media[16],const uint8_t shared[32],const uint8_t iv[16]);
int pc_audio_open(struct pc_audio *,int headless);
int pc_audio_open_timed(struct pc_audio *,int headless,const struct pc_playout *,const struct pc_clock *);
int pc_audio_sync(struct pc_audio *,const uint8_t *,size_t);
int pc_audio_ingress(struct pc_audio *,const uint8_t *,size_t);
int pc_audio_step(struct pc_audio *);
int pc_audio_end(struct pc_audio *);
int pc_audio_volume(struct pc_audio *,const uint8_t *,size_t);
uint64_t pc_audio_decoded(const struct pc_audio *);
void pc_audio_close(struct pc_audio *);
/* Pause only this stream; retain session keys for a later audio SETUP. */
void pc_audio_stop(struct pc_audio *);
#endif

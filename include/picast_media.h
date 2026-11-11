#ifndef PICAST_MEDIA_H
#define PICAST_MEDIA_H
/* Sound delay after the sender timestamp. Chosen by eye on one TV (r183, r184, r188). */
#include "picast_config.h"
#define PC_PLAYOUT_DEFAULT_MS ((unsigned)PC_CONFIG_DELAY_DEFAULT)  /* picast.txt: delay */
#include "picast_pair.h"
#include "picast_audio.h"
#include "picast_fairplay.h"
#include "picast_mirror.h"
#include "picast_mirror_crypto.h"
#include "picast_clock.h"
#include "picast_playout.h"
/* Bounded native video trial, not a general network server. All sockets are
 * created inside the same private namespace as the control socket. */
struct pc_media {
    int sockets[5], video_client, event_client;
    unsigned phase, configs, packets, video_packets, combined_info, recording;
    uint16_t sender_timing_port, sender_audio_control_port;
    struct pc_audio audio;
    uint8_t key[16], shared[32];
    struct pc_mirror_cipher cipher;
    struct pc_h264_config config;
    uint8_t header[128], *payload, *annex;
    size_t header_n, payload_n, bytes, pending_size;
    size_t byte_limit;
    unsigned packet_limit;
    uint8_t peer[6];
    double timing_sent;
    struct pc_clock clock;
    uint64_t timing_token, timing_sent_ns;
    uint64_t video_clock_samples, video_clock_unmapped;
    int64_t video_age_min_ns, video_age_max_ns;
#define PC_MEDIA_AGE_BUCKETS 120
#define PC_MEDIA_AGE_FLOOR_MS 200
    uint32_t video_age_hist[PC_MEDIA_AGE_BUCKETS];
    /* Presentation times follow the sender's spacing; clock updates slew in. */
    uint64_t smooth_remote, smooth_mapped;
    int smooth_valid;
    uint32_t clock_slews, clock_resets;
    unsigned timing_pending, timing_valid, timing_rejected;
    struct pc_playout playout;
    uint64_t pending_pts, clock_wait_since_ns;
    uint64_t video_align_ns;
    uint64_t first_video_ns, last_video_ns;
    struct pc_mirror_header packet;
    void *output;
};
int pc_media_tun_open(const uint8_t own[6],int *,int *,int sockets[5]);
int pc_media_open(struct pc_media *, const int sockets[5], const uint8_t peer[6]);
void pc_media_close(struct pc_media *);
int pc_media_setup(struct pc_media *,const struct pc_pair_verify *,const struct pc_fairplay *,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int pc_media_step(struct pc_media *);
int pc_media_combine(const uint8_t *,size_t,uint8_t *,size_t,size_t *);
int pc_media_reply_info(const uint8_t *,size_t,uint8_t *,size_t,size_t *);
/* Picture size offered to the sender for a display of this shape ("WIDTHxHEIGHT"). */
void pc_media_display_size(const char *screen,unsigned *width,unsigned *height);
/* PC_OK: audio-only stop; PC_OTHER: whole session; invalid: no mutation. */
int pc_media_teardown(struct pc_media *,const uint8_t *,size_t);
#endif

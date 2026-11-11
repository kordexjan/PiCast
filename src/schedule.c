#include "picast.h"
#include <string.h>

enum { AW_US = 16384, EAW_US = 65536, PSF_US = 112640, MIF_US = 524288 };

int pc_rx_clock_map(struct pc_rx_clock *clock, uint64_t tsft, uint64_t host, uint64_t *observed) {
    if (!clock || !observed || tsft > INT64_MAX || host > INT64_MAX) return PC_INVALID;
    int64_t offset = (int64_t)host - (int64_t)tsft;
    if (!clock->samples || tsft < clock->last_tsft) {
        if (clock->samples) clock->resets++;
        clock->offset_us = offset;
    } else if (offset < clock->offset_us) clock->offset_us = offset;
    /* offset <= host-tsft, so this addition cannot exceed host/INT64_MAX. */
    if (clock->offset_us < 0 && tsft < (uint64_t)-clock->offset_us) return PC_INVALID;
    *observed = clock->offset_us < 0 ? tsft - (uint64_t)-clock->offset_us : tsft + (uint64_t)clock->offset_us;
    clock->last_tsft = tsft;
    if (clock->samples < UINT32_MAX) clock->samples++;
    return PC_OK;
}

int pc_awdl_clock_project(const struct pc_awdl_sync *s, uint32_t phy, uint32_t target,
                          uint32_t elapsed, struct pc_awdl_clock *out) {
    if (!s || !out) return PC_INVALID;
    if (s->aw_period_tu != 16 || s->presence != 4 || s->tx_channel != 6 ||
        !s->tx_counter || s->tx_counter > 64) return PC_UNSUPPORTED;
    if (elapsed > PC_AWDL_MAX_AGE_US) return PC_OTHER;
    uint32_t delay = phy - target; /* intentional 32-bit peer clock wrap */
    if (delay > EAW_US) return PC_INVALID;
    uint32_t initial = EAW_US - s->tx_counter * 1024U;
    /* TU quantization can straddle an AW boundary by less than one TU.
     * Reject contradictory counters instead of accepting a new clock epoch. */
    unsigned aw = s->aw_counter % 4;
    if (aw != initial / AW_US && (!initial || aw != (initial - 1) / AW_US)) return PC_INVALID;
    uint32_t phase = initial + delay + elapsed;
    struct pc_awdl_clock value = {
        .aw_counter = (uint16_t)((s->aw_counter & 0xfffcU) + phase / AW_US),
        .remaining_us = EAW_US - phase % EAW_US
    };
    *out = value;
    return PC_OK;
}

static int unicast(const uint8_t *m) {
    static const uint8_t zero[6];
    return m && !(m[0] & 1) && memcmp(m, zero, 6);
}

int pc_awdl_peer_init(struct pc_awdl_peer *s, const uint8_t own[6], const uint8_t peer[6]) {
    if (!s || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6)) return PC_INVALID;
    struct pc_awdl_peer value = {0};
    memcpy(value.own, own, 6); memcpy(value.peer, peer, 6);
    *s = value;
    return PC_OK;
}

struct snapshot { struct pc_awdl_sync sync; struct pc_awdl_channels channels; int error; unsigned seen; };
static void snapshot_field(uint8_t type, const uint8_t *p, size_t n, void *ctx) {
    struct snapshot *f = ctx;
    unsigned bit = type == 4 ? 1 : type == 18 ? 2 : 0;
    if (!bit) return;
    if (f->seen & bit) f->error = PC_INVALID;
    f->seen |= bit;
    int result = type == 4 ? pc_awdl_sync_parse(p, n, &f->sync) : pc_awdl_channels_parse(p, n, &f->channels);
    if (result != PC_OK) f->error = result;
}

static uint32_t clock_position(const struct pc_awdl_clock *clock) {
    return (uint32_t)clock->aw_counter * AW_US + (EAW_US - clock->remaining_us) % AW_US;
}

int pc_awdl_peer_observe(struct pc_awdl_peer *s, const uint8_t *frame, size_t n, uint64_t now) {
    if (!s || !unicast(s->own) || !unicast(s->peer) || !frame) return PC_INVALID;
    if (n > sizeof(s->frame)) return PC_UNSUPPORTED;
    if (now > UINT64_MAX - 2U * PC_AWDL_MAX_AGE_US || (s->frame_size && now < s->observed_us)) return PC_INVALID;
    struct pc_awdl a; struct snapshot f = {0};
    int result = pc_awdl_parse(frame, n, &a, snapshot_field, &f);
    if (result != PC_OK) return result;
    if (memcmp(a.source, s->peer, 6)) return PC_OTHER;
    if (f.error || f.seen != 3) return f.error ? f.error : PC_INVALID;
    if (f.channels.count != 16 || f.channels.step != 3 || f.channels.duplicate || f.channels.fill != 0xffff)
        return PC_UNSUPPORTED;
    /* Reuse the original follower's election/loop validation before accepting
     * anything into persistent state. Build only into a temporary buffer. */
    uint8_t validation[400]; size_t written;
    result = pc_awdl_follow_build_at(s->own, frame, n, 0, 0, (uint32_t)now, 0,
                                     validation, sizeof(validation), &written);
    if (result != PC_OK) return result;
    struct pc_awdl_clock fresh;
    result = pc_awdl_clock_project(&f.sync, a.phy_time, a.target_time, 0, &fresh);
    if (result != PC_OK) return result;
    /* Reject repeated clock samples even after timeout. Otherwise replaying
     * one frozen announcement could repeatedly resurrect an expired peer. */
    if (s->frame_size && !memcmp(s->master, f.sync.master, 6) &&
        a.phy_time == s->phy_time && a.target_time == s->target_time && f.sync.aw_counter == s->sync.aw_counter)
        return PC_OTHER;
    int stable = 0;
    if (s->frame_size && now - s->observed_us <= PC_AWDL_MAX_AGE_US && !memcmp(s->master, f.sync.master, 6)) {
        struct pc_awdl_clock prior;
        if (pc_awdl_clock_project(&s->sync, s->phy_time, s->target_time, (uint32_t)(now - s->observed_us), &prior) == PC_OK) {
            uint32_t x = clock_position(&fresh), y = clock_position(&prior);
            uint32_t difference = x > y ? x - y : y - x;
            const uint32_t cycle = 65536U * AW_US;
            if (difference > cycle / 2) difference = cycle - difference;
            stable = difference <= 3 * 1024;
        }
    }
    if (!stable) {
        if (s->frame_size) {
            s->resyncs++;
            if (memcmp(s->master, f.sync.master, 6)) s->master_changes++;
            else if (now - s->observed_us > PC_AWDL_MAX_AGE_US) s->holdover_reacquisitions++;
            else s->clock_discontinuities++;
        }
        s->consistent_samples = 1;
        s->psf_due_us = s->mif_due_us = now;
    } else if (s->consistent_samples < 2) s->consistent_samples++;
    s->phase = s->consistent_samples >= 2 ? PC_PEER_TRACKING : PC_PEER_ACQUIRING;
    memcpy(s->master, f.sync.master, 6);
    s->sync = f.sync; s->channels = f.channels;
    s->phy_time = a.phy_time; s->target_time = a.target_time;
    s->observed_us = now; s->frame_size = n;
    memcpy(s->frame, frame, n);
    return PC_OK;
}

int pc_awdl_peer_poll(struct pc_awdl_peer *s, uint64_t now, struct pc_awdl_plan *out) {
    if (!s || !out) return PC_INVALID;
    if (!s->frame_size || s->phase == PC_PEER_EXPIRED) return PC_OTHER;
    if (now < s->observed_us) return PC_INVALID;
    if (now - s->observed_us > PC_AWDL_MAX_AGE_US) { s->phase = PC_PEER_EXPIRED; return PC_OTHER; }
    struct pc_awdl_plan p = {0};
    int result = pc_awdl_clock_project(&s->sync, s->phy_time, s->target_time,
                                      (uint32_t)(now - s->observed_us), &p.clock);
    if (result != PC_OK) return result;
    unsigned index = p.clock.aw_counter / 4U % 16U;
    p.channel = s->channels.number[index]; p.operating_class = s->channels.operating_class[index];
    p.next_wake_us = s->observed_us + PC_AWDL_MAX_AGE_US + 1;
    if (now >= s->psf_due_us) p.available |= PC_PEER_PSF;
    else if (s->psf_due_us < p.next_wake_us) p.next_wake_us = s->psf_due_us;
    uint32_t phase = EAW_US - p.clock.remaining_us;
    if (p.channel == 6 && p.operating_class == 81) {
        if (s->phase == PC_PEER_TRACKING && phase >= 3 * 1024 && p.clock.remaining_us >= 6 * 1024)
            p.available |= PC_PEER_DATA;
        if (now >= s->mif_due_us && phase >= 29 * 1024 && phase <= 35 * 1024)
            p.available |= PC_PEER_MIF;
    }
    /* Schedule guarded data windows and a MIF at a channel-6 EAW's center.
     * Never request channel changes: PiCast's radio stays on channel 6. */
    for (unsigned step = 0; step <= 16; step++) {
        unsigned slot = (index + step) % 16;
        if (s->channels.number[slot] != 6 || s->channels.operating_class[slot] != 81) continue;
        int64_t start = (int64_t)step * EAW_US - phase;
        int64_t data = start + 3 * 1024;
        int64_t center = start + 32 * 1024;
        if (s->phase == PC_PEER_TRACKING && data > 0 && now + (uint64_t)data < p.next_wake_us)
            p.next_wake_us = now + (uint64_t)data;
        if (center > 0 && now + (uint64_t)center >= s->mif_due_us && now + (uint64_t)center < p.next_wake_us)
            p.next_wake_us = now + (uint64_t)center;
    }
    if (p.available & (PC_PEER_PSF | PC_PEER_MIF)) p.next_wake_us = now;
    *out = p;
    return PC_OK;
}

int pc_awdl_peer_build(struct pc_awdl_peer *s, uint64_t now, unsigned event,
                       uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written = 0;
    if (event != PC_PEER_PSF && event != PC_PEER_MIF) return PC_INVALID;
    struct pc_awdl_plan plan;
    int result = pc_awdl_peer_poll(s, now, &plan);
    if (result != PC_OK) return result;
    if (!(plan.available & event)) return PC_OTHER;
    return pc_awdl_follow_build_at(s->own, s->frame, s->frame_size, (uint32_t)(now - s->observed_us),
                                   (uint16_t)(s->sequence + 1), (uint32_t)now,
                                   event == PC_PEER_MIF ? 3 : 0, out, capacity, written);
}

int pc_awdl_peer_mark_sent(struct pc_awdl_peer *s, uint64_t now, unsigned event) {
    if (event != PC_PEER_PSF && event != PC_PEER_MIF) return PC_INVALID;
    struct pc_awdl_plan plan;
    int result = pc_awdl_peer_poll(s, now, &plan);
    if (result != PC_OK) return result;
    if (!(plan.available & event)) return PC_OTHER;
    if (event == PC_PEER_PSF) s->psf_due_us = now + PSF_US;
    else s->mif_due_us = now + MIF_US;
    s->sequence++;
    return PC_OK;
}

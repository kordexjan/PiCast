#include "picast.h"
#include <stdio.h>
#include <string.h>

struct fields { const uint8_t *sync, *election, *channels; size_t sync_n, election_n, channels_n; unsigned duplicate; };
static void field(uint8_t type, const uint8_t *p, size_t n, void *ctx) {
    struct fields *f = ctx;
    if (type == 4) { if (f->sync) f->duplicate = 1; f->sync = p; f->sync_n = n; }
    if (type == 24) { if (f->election) f->duplicate = 1; f->election = p; f->election_n = n; }
    if (type == 18) { if (f->channels) f->duplicate = 1; f->channels = p; f->channels_n = n; }
}
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static size_t tag(uint8_t *p, uint8_t kind, const uint8_t *value, size_t n) {
    p[0] = kind; u16(p + 1, (uint16_t)n); memcpy(p + 3, value, n); return n + 3;
}

int pc_awdl_data_window(const uint8_t *peer, size_t size, uint32_t elapsed_us) {
    struct pc_awdl a; struct fields f = {0};
    struct pc_awdl_sync sync; struct pc_awdl_channels channels;
    int result = pc_awdl_parse(peer, size, &a, field, &f);
    if (result != PC_OK) return result;
    if (f.duplicate || !f.sync || !f.channels) return PC_INVALID;
    if (pc_awdl_sync_parse(f.sync, f.sync_n, &sync) != PC_OK ||
        pc_awdl_channels_parse(f.channels, f.channels_n, &channels) != PC_OK) return PC_UNSUPPORTED;
    /* Only the measured configuration has a known mapping. Zero entries mean
     * no advertised data availability, even when a PSF was heard on channel 6.
     * Formula and timing correction: Stute et al., arXiv:1808.03156, 6.2/6.3. */
    if (sync.aw_period_tu != 16 || sync.presence != 4 || sync.tx_channel != 6 ||
        channels.count != 16 || channels.step != 3 || channels.duplicate != 0 ||
        channels.fill != 0xffff || !sync.tx_counter || sync.tx_counter > 64) return PC_UNSUPPORTED;
    unsigned index = (sync.aw_counter / 4U) % 16U;
    if (channels.number[index] != 6 || channels.operating_class[index] != 81) return PC_OTHER;
    /* uint32 subtraction intentionally handles the peer's clock wrap. Reject
     * inconsistent timestamps rather than extrapolating to a later EAW. */
    uint32_t tx_delay = a.phy_time - a.target_time;
    int64_t remaining = (int64_t)sync.tx_counter * 1024 - tx_delay - elapsed_us;
    if (tx_delay > 65536 || remaining < 6 * 1024 || remaining > 61 * 1024) return PC_OTHER;
    return PC_OK;
}

/* A short text naming the peer's announced schedule, for diagnosis: transmit
 * channel, period, presence, slot count and step, and the distinct channels. */
int pc_awdl_schedule_key(const uint8_t *frame, size_t size, char *out, size_t capacity) {
    struct pc_awdl a; struct fields f = {0};
    struct pc_awdl_sync sync; struct pc_awdl_channels channels;
    if (!out || capacity < 16 || pc_awdl_parse(frame, size, &a, field, &f) != PC_OK || !f.sync || !f.channels) return -1;
    if (pc_awdl_sync_parse(f.sync, f.sync_n, &sync) != PC_OK) return -1;
    if (pc_awdl_channels_parse(f.channels, f.channels_n, &channels) != PC_OK) {
        snprintf(out, capacity, "tx%u p%u unparsed", sync.tx_channel, sync.aw_period_tu);
        return 0;
    }
    int n = snprintf(out, capacity, "tx%u p%u pr%u c%u s%u:", sync.tx_channel, sync.aw_period_tu, sync.presence, channels.count, channels.step);
    uint8_t seen[256] = {0};
    for (unsigned i = 0; i < channels.count && i < 256 && n > 0 && (size_t)n < capacity - 5; i++) {
        uint8_t c = channels.number[i];
        if (seen[c]) continue;
        seen[c] = 1;
        n += snprintf(out + n, capacity - (size_t)n, "%s%u", out[n - 1] == ':' ? "" : ",", c);
    }
    return 0;
}

static int profile_gaps = 0, profile_solo = 1;
void pc_awdl_follow_set_profile(int gaps, int solo) { profile_gaps = gaps; profile_solo = solo; }

int pc_awdl_follow_build_at(const uint8_t own[6], const uint8_t *peer, size_t peer_n,
                            uint32_t elapsed_us, uint16_t sequence, uint32_t clock_us, uint8_t subtype,
                            uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written = 0;
    const uint8_t zero[6] = {0};
    if (!own || !out || capacity < 300 || (own[0] & 1) || !memcmp(own, zero, 6) || (subtype != 0 && subtype != 3)) return PC_INVALID;
    struct pc_awdl a; struct fields f = {0}; struct pc_awdl_sync sync;
    struct pc_awdl_channels availability;
    int result = pc_awdl_parse(peer, peer_n, &a, field, &f);
    if (result != PC_OK) return result;
    if (f.duplicate || !f.sync || !f.election || !f.channels || f.election_n < 40 ||
        pc_awdl_sync_parse(f.sync, f.sync_n, &sync) != PC_OK) return PC_INVALID;
    result = pc_awdl_channels_parse(f.channels, f.channels_n, &availability);
    if (result != PC_OK) return result;
    if (availability.count != 16 || availability.step != 3 || availability.duplicate || availability.fill != 0xffff)
        return PC_UNSUPPORTED;
    uint32_t distance = u32(f.election + 16), metric = u32(f.election + 20);
    /* The peer's clock owner need not be the election root: with several Apple
     * devices nearby, senders report distance 2 or 3 with an intermediate clock
     * owner (931 of 3507 frames in r170). We follow the peer's own clock either
     * way, so only refuse what could make a loop or is not a real address. */
    if (sync.aw_period_tu != 16 || sync.tx_channel != 6 || distance >= 8 || metric <= 60 ||
        !memcmp(sync.master, own, 6) || !memcmp(f.election, own, 6) || !memcmp(f.election + 6, own, 6) ||
        !memcmp(a.source, own, 6) || (sync.master[0] & 1) || !memcmp(sync.master, zero, 6) ||
        (f.election[0] & 1) || !memcmp(f.election, zero, 6)) return PC_UNSUPPORTED;
    struct pc_awdl_clock projected;
    result = pc_awdl_clock_project(&sync, a.phy_time, a.target_time, elapsed_us, &projected);
    if (result != PC_OK) return result;
    uint16_t remaining_tu = (uint16_t)((projected.remaining_us + 1023) / 1024);
    uint32_t rounding_us = remaining_tu * 1024U - projected.remaining_us;
    /* Encode the sub-TU remainder in PHY-Target. The receiver reconstructs
     * the same EAW boundary, rather than a rounded boundary that drifts.
     * AW counter belongs to that rounded Target instant, not the later PHY. */
    uint16_t target_aw = (uint16_t)((projected.aw_counter & 0xfffcU) + (64U - remaining_tu) / 16U);
    /* Current captures carry three reserved trailing bytes in the standalone
     * sequence, and two in the legacy sequence nested in Sync Parameters. */
    uint8_t channels[41] = {15, 3, 0, 3, 0xff, 0xff};
    uint8_t timing[73] = {0};
    timing[0] = 6; u16(timing + 1, remaining_tu); timing[3] = sync.master_channel;
    timing[4] = sync.guard; u16(timing + 5, 16); u16(timing + 7, 110);
    u16(timing + 9, 0x1800); u16(timing + 11, 16); u16(timing + 13, 16);
    timing[17] = timing[18] = timing[19] = timing[20] = 3;
    memcpy(timing + 21, sync.master, 6); timing[27] = 4; u16(timing + 29, target_aw);
    timing[33] = 15; timing[34] = 1; timing[36] = 3;
    u16(timing + 37, 0xffff);
    /* This bounded probe keeps its radio on channel 6 throughout. Advertise
     * our actual availability, not the intersection with the remote radio's
     * schedule. Native peers reject an absent first sequence entry. Sending
     * is independently gated against the remote channel/time window. */
    for (unsigned i = 0; i < 16; i++) {
        /* gaps=3 is the shape a MacBook announced by itself in r184: 5 slots on, 3 off. */
        if (i % 8 >= 8U - (unsigned)profile_gaps) continue;
        channels[6 + 2 * i] = 6; channels[7 + 2 * i] = 81;
        timing[39 + 2 * i] = 0x2b; timing[40 + 2 * i] = 6;
    }
    /* The common window covers the first 16 TU of our 64-TU EAW. Report
     * its remaining duration, rather than declaring it already closed at
     * every instant. The channel intersection may make this slot absent. */
    unsigned current_slot = (target_aw / 4U) % 16U;
    if (channels[6 + 2 * current_slot] == 6 && remaining_tu > 48)
        u16(timing + 15, (uint16_t)(remaining_tu - 48));
    uint8_t election[40] = {0}, legacy[21] = {0};
    memcpy(election, f.election, 6); memcpy(election + 6, a.source, 6);
    put32(election + 12, u32(f.election + 12)); put32(election + 16, distance + 1);
    put32(election + 20, metric); put32(election + 24, 60); put32(election + 36, sequence);
    legacy[3] = (uint8_t)(distance + 1); memcpy(legacy + 5, f.election, 6);
    put32(legacy + 11, metric); put32(legacy + 15, 60);
    /* Only channel 6 and our own address; no dual-band capability. */
    /* The native parser consumes country[3] and social-channels[2] before
     * optional addresses, even for the classic profile. Include both fields
     * explicitly: X0 is unspecified country, not a regulatory-domain change.
     * 0x0304 = country, social channels and our own AWDL address only. */
    uint8_t datapath[13] = {4, 3, 'X', '0', 0, 1, 0};
    /* Identify the announced AirPlay sink on the AWDL link as well as in DNS-SD. */
    datapath[0] |= 0x40;
    /* The Pi has no infrastructure association while it advertises, so Data
     * Path State bit 10 reports AirPlay Solo Mode. */
    if (profile_solo) datapath[1] |= 0x04;
    /* Channel role: PiCast follows the sender's timing and advertises only its
     * actual channel-6 slots. Bit 7 asks the sender to account for that
     * sequence; it does not add 5 GHz support. */
    datapath[0] |= 0x80;
    memcpy(datapath + 7, own, 6);
    const uint8_t services[9] = {0}; /* no DNS-SD services advertised */
    /* Measured Zero 2 W capabilities: HT20, static SMPS, SGI20, one stream,
     * AMPDU exponent 3 / spacing 7; no imported Apple HT/VHT capabilities. */
    const uint8_t ht[8] = {0, 0, 0x20, 0x10, 0x1f, 0xff, 0, 0};
    /* Classic AWDL 3.4 wire profile; PiCast does not claim a current Apple
     * peer's protocol version. */
    const uint8_t version[2] = {0x34, 1};
    const uint8_t arpa[] = {3, 6, 'p', 'i', 'c', 'a', 's', 't', 0xc0, 0x0c};
    memset(out, 0, 40); out[0] = 0xd0; memset(out + 4, 0xff, 6); memcpy(out + 10, own, 6);
    const uint8_t bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73}; memcpy(out + 16, bssid, 6);
    u16(out + 22, (uint16_t)((sequence & 0xfff) << 4));
    const uint8_t fixed[8] = {0x7f, 0, 0x17, 0xf2, 8, 0x10, 3, 0}; memcpy(out + 24, fixed, 8);
    out[30] = subtype;
    put32(out + 32, clock_us); put32(out + 36, clock_us - rounding_us);
    size_t n = 40;
    n += tag(out + n, 4, timing, sizeof(timing));
    n += tag(out + n, 5, legacy, sizeof(legacy));
    n += tag(out + n, 18, channels, sizeof(channels));
    n += tag(out + n, 24, election, sizeof(election));
    n += tag(out + n, 6, services, sizeof(services));
    if (subtype == 3) n += tag(out + n, 7, ht, sizeof(ht));
    if (subtype == 3) n += tag(out + n, 16, arpa, sizeof(arpa));
    n += tag(out + n, 12, datapath, sizeof(datapath));
    n += tag(out + n, 21, version, sizeof(version));
    *written = n;
    return PC_OK;
}

int pc_awdl_follow_build(const uint8_t own[6], const uint8_t *peer, size_t peer_n,
                         uint16_t sequence, uint32_t clock_us, uint8_t subtype,
                         uint8_t *out, size_t capacity, size_t *written) {
    return pc_awdl_follow_build_at(own, peer, peer_n, 0, sequence, clock_us, subtype, out, capacity, written);
}

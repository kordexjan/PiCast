#include "picast.h"
#include <assert.h>
#include <string.h>

static const uint8_t own[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 5, 6, 7, 8, 9};
static void le16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint32_t v) {
    for (unsigned j = 0; j < 4; j++) p[j] = (uint8_t)(v >> (8 * j));
}
static void fixture(uint8_t frame[160], unsigned aw, unsigned remaining_tu, uint32_t timestamp) {
    memset(frame, 0, 160); frame[0] = 0xd0; memcpy(frame + 10, peer, 6);
    memcpy(frame + 24, "\x7f\x00\x17\xf2\x08\x10\x03\x00", 8);
    le32(frame + 32, timestamp); le32(frame + 36, timestamp);
    frame[40] = 4; frame[41] = 33;
    uint8_t *s = frame + 43;
    s[0] = s[3] = 6; le16(s + 1, remaining_tu); s[5] = 16;
    memcpy(s + 21, peer, 6); s[27] = 4; le16(s + 29, aw);
    frame[76] = 18; frame[77] = 38;
    uint8_t *c = frame + 79;
    c[0] = 15; c[1] = 3; c[3] = 3; c[4] = c[5] = 255;
    for (unsigned j = 0; j < 16; j++) { c[6 + 2 * j] = 6; c[7 + 2 * j] = 81; }
    frame[117] = 24; frame[118] = 40;
    memcpy(frame + 120, peer, 6); memcpy(frame + 126, peer, 6);
    le32(frame + 140, 510); le32(frame + 144, 510);
}

struct timing { struct pc_awdl_sync sync; };
static void timing(uint8_t type, const uint8_t *p, size_t n, void *ctx) {
    if (type == 4) assert(pc_awdl_sync_parse(p, n, &((struct timing *)ctx)->sync) == PC_OK);
}

void test_schedule(void) {
    struct pc_rx_clock rx = {0}; uint64_t observed;
    assert(pc_rx_clock_map(&rx, 1000, 5000, &observed) == PC_OK && observed == 5000);
    assert(pc_rx_clock_map(&rx, 2000, 6200, &observed) == PC_OK && observed == 6000);
    assert(pc_rx_clock_map(&rx, 3000, 6900, &observed) == PC_OK && observed == 6900);
    assert(pc_rx_clock_map(&rx, 4000, 8200, &observed) == PC_OK && observed == 7900);
    assert(pc_rx_clock_map(&rx, 0, 9000, &observed) == PC_OK && observed == 9000 && rx.resets == 1);
    struct pc_rx_clock rx_saved = rx;
    observed = 123;
    assert(pc_rx_clock_map(&rx, UINT64_MAX, 10000, &observed) == PC_INVALID && observed == 123 && !memcmp(&rx, &rx_saved, sizeof(rx)));
    rx = (struct pc_rx_clock){0};
    assert(pc_rx_clock_map(&rx, 5000, 1000, &observed) == PC_OK && observed == 1000);
    assert(pc_rx_clock_map(&rx, 6000, 2300, &observed) == PC_OK && observed == 2000);

    /* Extended present bitmap moves TSFT to the next 8-byte boundary. */
    uint8_t radiotap[39] = {0};
    radiotap[2] = 24; radiotap[4] = 1; radiotap[7] = 0x80;
    le32(radiotap + 16, 0x44332211); le32(radiotap + 20, 0x88776655);
    struct pc_radiotap_view view;
    assert(pc_radiotap_parse(radiotap, 34, &view) == PC_OK && view.has_tsft &&
           view.tsft_us == UINT64_C(0x8877665544332211) && view.frame == radiotap + 24 && view.frame_size == 10);
    struct pc_radiotap_view view_saved = view;
    radiotap[2] = 23;
    assert(pc_radiotap_parse(radiotap, 34, &view) == PC_INVALID && !memcmp(&view, &view_saved, sizeof(view)));
    radiotap[2] = 25; radiotap[4] = 3; radiotap[24] = 0x10;
    assert(pc_radiotap_parse(radiotap, 39, &view) == PC_OK && view.flags == 0x10 && view.frame_size == 10);
    radiotap[24] = 0x40;
    assert(pc_radiotap_parse(radiotap, 39, &view) == PC_INVALID);

    struct pc_awdl_sync s = {.tx_channel = 6, .aw_period_tu = 16, .presence = 4, .tx_counter = 64};
    struct pc_awdl_clock clock;
    assert(pc_awdl_clock_project(&s, 0, 0, 0, &clock) == PC_OK && clock.aw_counter == 0 && clock.remaining_us == 65536);
    assert(pc_awdl_clock_project(&s, 0, 0, 16384, &clock) == PC_OK && clock.aw_counter == 1 && clock.remaining_us == 49152);
    assert(pc_awdl_clock_project(&s, 0, 0, 65536, &clock) == PC_OK && clock.aw_counter == 4 && clock.remaining_us == 65536);
    assert(pc_awdl_clock_project(&s, 0, 0, 1048576, &clock) == PC_OK && clock.aw_counter == 64);
    s.aw_counter = 65535; s.tx_counter = 1;
    assert(pc_awdl_clock_project(&s, 0, 0, 1024, &clock) == PC_OK && clock.aw_counter == 0 && clock.remaining_us == 65536);
    assert(pc_awdl_clock_project(&s, 3, 0xfffffffcU, 0, &clock) == PC_OK && clock.aw_counter == 65535 && clock.remaining_us == 1017);
    struct pc_awdl_clock saved_clock = clock;
    assert(pc_awdl_clock_project(&s, 0, 1, 0, &clock) == PC_INVALID && !memcmp(&clock, &saved_clock, sizeof(clock)));
    assert(pc_awdl_clock_project(&s, 0, 0, PC_AWDL_MAX_AGE_US + 1, &clock) == PC_OTHER);
    s.aw_counter = 0;
    assert(pc_awdl_clock_project(&s, 0, 0, 0, &clock) == PC_INVALID); /* contradictory counter/phase */

    struct pc_awdl_peer state;
    assert(pc_awdl_peer_init(&state, own, peer) == PC_OK && state.phase == PC_PEER_LISTENING);
    struct pc_awdl_plan plan;
    assert(pc_awdl_peer_poll(&state, 0, &plan) == PC_OTHER);
    uint8_t frame[160], output[400]; size_t written;
    fixture(frame, 0, 64, 0);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 0) == PC_OK);
    assert(state.phase == PC_PEER_ACQUIRING && state.consistent_samples == 1);
    assert(pc_awdl_peer_poll(&state, 0, &plan) == PC_OK && plan.available == PC_PEER_PSF && plan.next_wake_us == 0);
    assert(pc_awdl_peer_build(&state, 0, PC_PEER_PSF, output, sizeof(output), &written) == PC_OK);
    assert(state.sequence == 0); /* preview/build is not a successful send */
    assert(pc_awdl_peer_mark_sent(&state, 0, PC_PEER_DATA) == PC_INVALID);
    assert(pc_awdl_peer_mark_sent(&state, 0, PC_PEER_PSF) == PC_OK && state.sequence == 1);
    assert(pc_awdl_peer_poll(&state, 0, &plan) == PC_OK && !plan.available && plan.next_wake_us == 32768);
    assert(pc_awdl_peer_poll(&state, 32768, &plan) == PC_OK && plan.available == PC_PEER_MIF);
    assert(pc_awdl_peer_mark_sent(&state, 32768, PC_PEER_MIF) == PC_OK);
    assert(pc_awdl_peer_build(&state, 32768, PC_PEER_MIF, output, sizeof(output), &written) == PC_OTHER && !written);

    /* A duplicate must not masquerade as a second synchronization sample. */
    struct pc_awdl_peer unchanged = state;
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 100000) == PC_OTHER && !memcmp(&state, &unchanged, sizeof(state)));
    fixture(frame, 4, 64, 65536);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 65536) == PC_OK && state.phase == PC_PEER_TRACKING);
    assert(pc_awdl_peer_poll(&state, 65536 + 3000, &plan) == PC_OK && !(plan.available & PC_PEER_DATA));
    assert(pc_awdl_peer_poll(&state, 65536 + 3072, &plan) == PC_OK && (plan.available & PC_PEER_DATA));
    assert(pc_awdl_peer_poll(&state, 65536 + 60000, &plan) == PC_OK && !(plan.available & PC_PEER_DATA));

    /* Unknown/malformed or foreign observations leave persistent state intact. */
    unchanged = state; frame[10] ^= 2;
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 70000) == PC_OTHER && !memcmp(&state, &unchanged, sizeof(state)));
    frame[10] ^= 2;
    assert(pc_awdl_peer_observe(&state, frame, 159, 70000) == PC_INVALID && !memcmp(&state, &unchanged, sizeof(state)));
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 1) == PC_INVALID && !memcmp(&state, &unchanged, sizeof(state)));

    /* Long holdover advances both the AW counter and channel-sequence index. */
    assert(pc_awdl_peer_poll(&state, 65536 + 1048576 + 10000, &plan) == PC_OK);
    assert(plan.clock.aw_counter == 68 && plan.clock.remaining_us == 55536 && (plan.available & PC_PEER_PSF));
    assert(pc_awdl_peer_build(&state, 65536 + 1048576 + 10000, PC_PEER_PSF, output, sizeof(output), &written) == PC_OK);
    struct pc_awdl a; struct timing t = {0};
    assert(pc_awdl_parse(output, written, &a, timing, &t) == PC_OK);
    assert(a.phy_time - a.target_time == 784); /* sub-TU remainder, not accumulated drift */
    assert(pc_awdl_clock_project(&t.sync, a.phy_time, a.target_time, 0, &clock) == PC_OK);
    assert(clock.aw_counter == plan.clock.aw_counter && clock.remaining_us == plan.clock.remaining_us);
    assert(pc_awdl_peer_poll(&state, 65536 + PC_AWDL_MAX_AGE_US + 1, &plan) == PC_OTHER && state.phase == PC_PEER_EXPIRED);
    assert(pc_awdl_peer_build(&state, 65536 + PC_AWDL_MAX_AGE_US + 1, PC_PEER_PSF, output, sizeof(output), &written) == PC_OTHER && !written);
    unchanged = state;
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 65536 + PC_AWDL_MAX_AGE_US + 2) == PC_OTHER &&
           !memcmp(&state, &unchanged, sizeof(state)));

    /* Reacquire; a different phase with the same master starts acquisition,
     * while two coherent fresh samples restore local tracking. */
    fixture(frame, 100, 64, 1000000);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 2000000) == PC_OK && state.phase == PC_PEER_ACQUIRING);
    assert(state.resyncs == 1 && state.holdover_reacquisitions == 1 && !state.clock_discontinuities);
    fixture(frame, 104, 64, 1065536);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 2065536) == PC_OK && state.phase == PC_PEER_TRACKING);
    fixture(frame, 200, 64, 1131072);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 2131072) == PC_OK && state.phase == PC_PEER_ACQUIRING);

    assert(state.resyncs == 2 && state.clock_discontinuities == 1 && !state.master_changes);

    /* All no-data slots suppress MIF/data, but do not suppress periodic PSF. */
    for (unsigned j = 0; j < 16; j++) frame[85 + 2 * j] = 0;
    le32(frame + 32, 1131073); le32(frame + 36, 1131073);
    assert(pc_awdl_peer_observe(&state, frame, sizeof(frame), 2131073) == PC_OK);
    assert(pc_awdl_peer_poll(&state, 2163840, &plan) == PC_OK && !(plan.available & (PC_PEER_MIF | PC_PEER_DATA)));
}

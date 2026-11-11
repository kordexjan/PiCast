#include "picast.h"
#include "picast_rtsp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_fcs_padding(void) {
    /* Independent zlib CRC32 vector for the 24-byte synthetic frame. */
    uint8_t rt[55] = {0,0,9,0,2,0,0,0,0x10};
    memcpy(rt+9,"123456789123456789123456",24);
    uint32_t crc = 0xb4e6096f;
    for (unsigned i=0;i<4;i++) rt[33+i]=(uint8_t)(crc>>(8*i));
    const uint8_t *frame; size_t size;
    for (size_t pad=0;pad<=16;pad++) {
        assert(pc_radiotap(rt,37+pad,&frame,&size)==PC_OK && size==24);
    }
    assert(pc_radiotap(rt,54,&frame,&size)==PC_OK && size==41);
    rt[33]^=1;
    assert(pc_radiotap(rt,47,&frame,&size)==PC_OK && size==34);
    rt[33]^=1;rt[40]=1;
    assert(pc_radiotap(rt,47,&frame,&size)==PC_OK && size==34);
}

static size_t callbacks;
void test_data(void);
void test_rtsp(void);
void test_aggregate(void);
void test_schedule(void);
void test_follow(void);
void test_mdns(void);
void test_mdns_group(void);
void test_service(void);
void test_udp(void);
void test_neighbor(void);
void test_mirror(void);
static void item(uint8_t type, const uint8_t *value, size_t n, void *ctx) {
    (void)type; (void)value; (void)n; (void)ctx; callbacks++;
}
static void report(const uint8_t *value, size_t n, int rssi, void *ctx) {
    (void)value; (void)n; (void)ctx;
    assert(rssi == -42); callbacks++;
}
static uint32_t rng = 7;
static uint8_t random_byte(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return (uint8_t)rng;
}

int main(void) {
    test_mirror();
    test_rtsp();
    test_data();
    test_aggregate();
    test_schedule();
    test_follow();
    test_mdns();
    test_mdns_group();
    test_service();
    test_udp();
    test_neighbor();
    uint8_t sync_bytes[33] = {6, 0x34, 0x12, 6, 0, 16, 0, 110, 0};
    sync_bytes[21] = 2; sync_bytes[27] = 4; sync_bytes[29] = 0xfe; sync_bytes[30] = 0xff;
    struct pc_awdl_sync sync;
    assert(pc_awdl_sync_parse(sync_bytes, sizeof(sync_bytes), &sync) == PC_OK);
    assert(sync.tx_channel == 6 && sync.master_channel == 6 && sync.tx_counter == 0x1234);
    assert(sync.aw_period_tu == 16 && sync.action_period_tu == 110 && sync.aw_counter == 65534);
    assert(sync.master[0] == 2 && sync.presence == 4);
    for (size_t i = 0; i < sizeof(sync_bytes); i++)
        assert(pc_awdl_sync_parse(sync_bytes, i, &sync) == PC_INVALID);
    uint8_t sequence[518] = {1, 3, 0, 3, 0xff, 0xff, 6, 81, 149, 128};
    struct pc_awdl_channels channels;
    assert(pc_awdl_channels_parse(sequence, 10, &channels) == PC_OK);
    assert(channels.count == 2 && channels.fill == 65535 && channels.step == 3);
    assert(channels.number[0] == 6 && channels.operating_class[0] == 81 && channels.number[1] == 149);
    for (size_t i = 0; i < 10; i++)
        assert(pc_awdl_channels_parse(sequence, i, &channels) == PC_INVALID);
    sequence[0] = 255;
    assert(pc_awdl_channels_parse(sequence, sizeof(sequence), &channels) == PC_OK && channels.count == 256);
    sequence[1] = 2;
    assert(pc_awdl_channels_parse(sequence, sizeof(sequence), &channels) == PC_UNSUPPORTED);
    uint8_t pcap_header[24], pcap_record[16];
    const uint8_t expected_header[24] = {
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 127, 0, 0, 0
    };
    const uint8_t expected_record[16] = {4, 3, 2, 1, 0x3f, 0x42, 0x0f, 0, 40, 0, 0, 0, 40, 0, 0, 0};
    assert(pc_pcap_header(pcap_header, 127) == PC_OK);
    assert(!memcmp(pcap_header, expected_header, 24));
    assert(pc_pcap_header(pcap_header, 1) == PC_INVALID);
    assert(pc_pcap_record(pcap_record, 0x01020304, 999999, 40) == PC_OK);
    assert(!memcmp(pcap_record, expected_record, 16));
    assert(pc_pcap_record(pcap_record, 0, 1000000, 40) == PC_INVALID);
    assert(pc_pcap_record(pcap_record, 0, 0, 65536) == PC_INVALID);
    /* Synthetic format vectors, never claimed as captured iPhone traffic. */
    uint8_t awdl[48] = {0xd0};
    const uint8_t prefix[] = {0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10, 0x03, 0,
                              0x78, 0x56, 0x34, 0x12, 1, 0, 0, 0,
                              0xfe, 2, 0, 0xab, 0xcd, 0xff, 0, 0};
    memcpy(awdl + 24, prefix, sizeof(prefix));
    struct pc_awdl a;
    callbacks = 0;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, item, NULL) == PC_OK);
    assert(a.tags == 2 && a.phy_time == 0x12345678 && a.target_time == 1 && callbacks == 2);
    for (size_t i = 0; i < sizeof(awdl); i++) {
        callbacks = 0;
        int rc = pc_awdl_parse(awdl, i, &a, item, NULL);
        /* 40 (no tags) and 45 (one tag) are complete packets too. */
        if (i == 40 || i == 45) assert(rc == PC_OK);
        else { assert(rc != PC_OK); assert(callbacks == 0); }
    }
    awdl[41] = 255;
    callbacks = 0;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, item, NULL) == PC_INVALID && !callbacks);
    awdl[41] = 2; awdl[1] = 0x40;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, NULL, NULL) == PC_UNSUPPORTED);
    awdl[1] = 0; awdl[29] = 0x20;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, NULL, NULL) == PC_UNSUPPORTED);
    awdl[1] = 0x80; awdl[29] = 0x10;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, NULL, NULL) == PC_UNSUPPORTED);
    awdl[1] = 0;
    awdl[29] = 0x10; awdl[25] = 0xff;
    assert(pc_awdl_parse(awdl, sizeof(awdl), &a, NULL, NULL) == PC_OTHER);

    const uint8_t ble[] = {2, 1, 6, 15, 0xff, 0x4c, 0, 9, 6, 3, 7, 10, 0, 0, 1,
                           0x16, 2, 0xab, 0xcd};
    struct pc_ble b;
    callbacks = 0;
    assert(pc_ble_parse(ble, sizeof(ble), &b, item, NULL) == PC_OK);
    assert(b.apple_records == 1 && b.airplay_records == 1 && b.peer_records == 1 && callbacks == 2);
    for (size_t i = 4; i < sizeof(ble); i++) {
        callbacks = 0;
        assert(pc_ble_parse(ble, i, &b, item, NULL) == PC_INVALID && !callbacks);
    }
    uint8_t broken[sizeof(ble)]; memcpy(broken, ble, sizeof(ble));
    broken[16] = 3;
    callbacks = 0;
    assert(pc_ble_parse(broken, sizeof(broken), &b, item, NULL) == PC_INVALID && !callbacks);
    const uint8_t padding[] = {0, 0, 0}, not_padding[] = {0, 0, 1};
    assert(pc_ble_parse(padding, sizeof(padding), &b, NULL, NULL) == PC_OK);
    assert(pc_ble_parse(not_padding, sizeof(not_padding), &b, NULL, NULL) == PC_INVALID);

    uint8_t rt[64] = {0, 0, 16, 0, 2, 0, 0, 0, 0x10};
    memcpy(rt + 16, awdl, 40);
    const uint8_t *frame; size_t n;
    assert(pc_radiotap(rt, 60, &frame, &n) == PC_OK && frame == rt + 16 && n == 40);
    rt[8] = 0x40;
    assert(pc_radiotap(rt, 60, &frame, &n) == PC_INVALID);
    rt[8] = 0x10; rt[7] = 0x80; rt[11] = 0x80; rt[15] = 0x80;
    assert(pc_radiotap(rt, 60, &frame, &n) == PC_INVALID);
    /* Extended presence word, aligned TSFT, then flags. */
    uint8_t extended[32] = {0,0,25,0,3,0,0,0x80};
    extended[24] = 0x10;
    assert(pc_radiotap(extended, sizeof(extended), &frame, &n) == PC_OK && n == 3);

    uint8_t event[34] = {4, 0x3e, 31, 2, 1};
    event[13] = sizeof(ble);
    memcpy(event + 14, ble, sizeof(ble)); event[33] = 214;
    callbacks = 0;
    assert(pc_ble_reports(event, sizeof(event), report, NULL) == PC_OK && callbacks == 1);
    for (size_t i = 0; i < sizeof(event); i++) {
        callbacks = 0;
        assert(pc_ble_reports(event, i, report, NULL) != PC_OK && !callbacks);
    }
    event[4] = 2; callbacks = 0;
    assert(pc_ble_reports(event, sizeof(event), report, NULL) == PC_INVALID && !callbacks);
    event[4] = 1; event[13] = 32;
    assert(pc_ble_reports(event, sizeof(event), NULL, NULL) == PC_INVALID);

    uint8_t attrs[12] = {0};
    uint16_t attr_len = 5, attr_type = 0x8003;
    memcpy(attrs, &attr_len, 2); memcpy(attrs + 2, &attr_type, 2); attrs[4] = 0xab;
    assert(pc_netlink_attr(attrs, 8, 3, &frame, &n) == PC_OK && n == 1 && frame[0] == 0xab);
    assert(pc_netlink_attr(attrs, 8, 4, &frame, &n) == PC_OTHER && frame == NULL);
    assert(pc_netlink_attr(attrs, 5, 3, &frame, &n) == PC_INVALID);
    attr_len = 3; memcpy(attrs + 8, &attr_len, 2);
    /* A valid first attribute must not escape a malformed later attribute. */
    frame = NULL;
    assert(pc_netlink_attr(attrs, 12, 3, &frame, &n) == PC_INVALID && frame == NULL);

    /* Deterministic hostile-input sweep, including recognizable prefixes.
     * Sanitizers catch out-of-bounds/undefined operations. Not a fuzzer proof. */
    uint8_t noise[512];
    for (unsigned i = 0; i < 25000; i++) {
        for (size_t j = 0; j < sizeof(noise); j++) noise[j] = random_byte();
        size_t size = ((size_t)random_byte() * 2) % sizeof(noise);
        struct pc_rtsp_request rtsp;
        (void)pc_rtsp_parse(noise, size, &rtsp);
        (void)pc_awdl_parse(noise, size, &a, NULL, NULL);
        struct pc_awdl_data data;
        (void)pc_awdl_data_parse(noise, size, &data);
        (void)pc_awdl_data_visit(noise, size, NULL, NULL);
        /* Exercise aggregate/header bounds past the 802.11 discriminator. */
        noise[0] = 0x88; noise[1] = 0; noise[22] = 0; noise[24] |= 0x80;
        memcpy(noise + 16, "\x00\x25\x00\xff\x94\x73", 6);
        (void)pc_awdl_data_visit(noise, size, NULL, NULL);
        (void)pc_awdl_sync_parse(noise, size, &sync);
        (void)pc_awdl_channels_parse(noise, size, &channels);
        noise[0] = 0xd0; noise[1] = 0; noise[22] = 0;
        memcpy(noise + 24, prefix, 16);
        (void)pc_awdl_parse(noise, size, &a, NULL, NULL);
        (void)pc_ble_parse(noise, size, &b, NULL, NULL);
        (void)pc_radiotap(noise, size, &frame, &n);
        (void)pc_netlink_attr(noise, size, 3, &frame, &n);
        noise[0] = 4; noise[1] = 0x3e;
        (void)pc_ble_reports(noise, size, NULL, NULL);
    }
    test_fcs_padding();
    puts("Protocol tests passed (synthetic vectors + 25000 hostile-input cases).");
    return 0;
}

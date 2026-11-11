#include "picast.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void fixture(const char *hex, uint8_t *out, size_t n) {
    assert(strlen(hex) == n * 2);
    for (size_t i = 0; i < n; i++) {
        unsigned value;
        assert(sscanf(hex + 2 * i, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
}

void test_data(void) {
    const uint8_t own[6] = {2, 1, 2, 3, 4, 5};
    const uint8_t peer[6] = {0xb2, 0x51, 0xf4, 0x14, 0x31, 0x54};
    const uint8_t nonce[8] = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t expected[56], reply[56], ip[56], frame[128]; size_t written;
    fixture("6000000000103a40fe80000000000000000102fffe030405fe80000000000000b051f4fffe14315480001ddd1234abcd0011223344556677", expected, 56);
    fixture("6000000000103a40fe80000000000000b051f4fffe143154fe80000000000000000102fffe03040581001cdd1234abcd0011223344556677", reply, 56);
    assert(pc_echo_build(own, peer, 0x1234, 0xabcd, nonce, ip) == PC_OK);
    assert(!memcmp(ip, expected, 56)); /* independent IPv6/pseudoheader checksum vector */
    uint8_t response[1500]; size_t response_size;
    assert(pc_echo_respond(ip, 56, peer, own, response, sizeof(response), &response_size) == PC_OK);
    assert(response_size == 56 && !memcmp(response, reply, 56));
    response[0] = 0xaa;
    assert(pc_echo_respond(ip, 56, own, peer, response, sizeof(response), &response_size) == PC_OTHER && !response_size && response[0] == 0xaa);
    assert(pc_echo_respond(ip, 56, peer, own, response, 55, &response_size) == PC_INVALID && !response_size && response[0] == 0xaa);
    ip[55] ^= 1;
    assert(pc_echo_respond(ip, 56, peer, own, response, sizeof(response), &response_size) == PC_INVALID && !response_size && response[0] == 0xaa);
    ip[55] ^= 1;
    assert(pc_echo_reply(reply, 56, own, peer, 0x1234, 0xabcd, nonce) == PC_OK);
    assert(pc_echo_reply(ip, 56, own, peer, 0x1234, 0xabcd, nonce) == PC_OTHER);
    assert(pc_echo_reply(reply, 56, own, peer, 0x1234, 1, nonce) == PC_OTHER);
    reply[42] ^= 1;
    assert(pc_echo_reply(reply, 56, own, peer, 0x1234, 0xabcd, nonce) == PC_INVALID);
    for (size_t n = 0; n < 56; n++)
        assert(pc_echo_reply(reply, n, own, peer, 0x1234, 0xabcd, nonce) == PC_INVALID);
    assert(pc_awdl_data_build(own, peer, 65535, ip, 56, frame, sizeof(frame), &written) == PC_OK);
    assert(written == 98 && frame[22] == 0xf0 && frame[23] == 0xff && frame[24] == 6);
    assert(!memcmp(frame + 26, "\xaa\xaa\x03\x00\x17\xf2\x08\x00", 8));
    assert(!memcmp(frame + 34, "\x03\x04\xff\xff\x00\x00\x86\xdd", 8));
    struct pc_awdl_data data;
    assert(pc_awdl_data_parse(frame, written, &data) == PC_OK);
    assert(data.sequence == 65535 && data.ipv6_size == 56 && !memcmp(data.ipv6, ip, 56));
    assert(!memcmp(data.source, own, 6) && !memcmp(data.destination, peer, 6));
    for (size_t n = 0; n < written; n++) {
        data.ipv6_size = 999;
        assert(pc_awdl_data_parse(frame, n, &data) == PC_INVALID && data.ipv6_size == 999);
    }
    frame[1] = 0x40;
    assert(pc_awdl_data_parse(frame, written, &data) == PC_UNSUPPORTED);
    frame[1] = 1;
    assert(pc_awdl_data_parse(frame, written, &data) == PC_OTHER);
    frame[1] = 0; frame[24] = 0x80;
    assert(pc_awdl_data_parse(frame, written, &data) == PC_INVALID);
    frame[24] = 0; frame[38] = 3;
    assert(pc_awdl_data_parse(frame, written, &data) == PC_INVALID);
    assert(pc_awdl_data_build(own, peer, 1, ip, 56, frame, 97, &written) == PC_INVALID && written == 0);
    uint8_t tcp_ip[60] = {0x60}; tcp_ip[5] = 20; tcp_ip[6] = 6;
    assert(pc_awdl_data_build(own, peer, 2, tcp_ip, sizeof(tcp_ip), frame, sizeof(frame), &written) == PC_OK && frame[24] == 0);
    ip[5] = 17;
    assert(pc_awdl_data_build(own, peer, 1, ip, 56, frame, sizeof(frame), &written) == PC_INVALID);
}

struct datagrams { unsigned count, aggregate, long_header; uint16_t sequence[64]; };
static void datagram(const struct pc_awdl_data *data, void *ctx) {
    struct datagrams *d = ctx;
    assert(d->count < 64 && data->ipv6_size == 56 && data->ipv6[0] == 0x60);
    d->sequence[d->count++] = data->sequence;
    d->aggregate += data->aggregate; d->long_header += data->long_header;
}

void test_aggregate(void) {
    const uint8_t own[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 5, 6, 7, 8, 9};
    uint8_t body[72], aggregate[8192] = {0}, regular[256] = {0};
    /* Independent wire fixture: 8-byte LLC, 8-byte AWDL, IPv6 Echo payload.
     * This is synthetic, not a recorded peer response. */
    fixture("aaaa030017f2080003040100000086dd6000000000103a40fe80000000000000000102fffe030405fe80000000000000b051f4fffe14315480001ddd1234abcd0011223344556677", body, 72);
    aggregate[0] = regular[0] = 0x88;
    memcpy(aggregate + 4, peer, 6); memcpy(aggregate + 10, own, 6);
    memcpy(aggregate + 16, "\x00\x25\x00\xff\x94\x73", 6);
    memcpy(regular, aggregate, 26);
    aggregate[24] = 0x86; regular[24] = 6;
    /* Long header: opening marker, an opaque short TLV, closing marker. */
    memcpy(regular + 26, body, 12);
    fixture("0300fe02abcd03018686dd", regular + 38, 11);
    memcpy(regular + 49, body + 16, 56);
    struct pc_awdl_data single;
    assert(pc_awdl_data_parse(regular, 105, &single) == PC_OK && single.long_header && !single.aggregate);
    assert(single.sequence == 1 && single.ipv6 == regular + 49);
    for (size_t n = 26; n < 105; n++)
        assert(pc_awdl_data_parse(regular, n, &single) != PC_OK);
    regular[39] = 255;
    assert(pc_awdl_data_parse(regular, 105, &single) == PC_INVALID);
    regular[39] = 0;
    regular[41] = 255;
    assert(pc_awdl_data_parse(regular, 105, &single) == PC_INVALID);
    regular[41] = 2;

    /* Subframe 1: DA, SA, big-endian length 72, then two padding bytes.
     * Subframe 2 carries the longer header; final subframe has no padding. */
    memcpy(aggregate + 26, peer, 6); memcpy(aggregate + 32, own, 6);
    aggregate[39] = 72; memcpy(aggregate + 40, body, 72);
    aggregate[112] = 0x5a; aggregate[113] = 0xa5; /* unspecified padding values */
    memcpy(aggregate + 114, peer, 6); memcpy(aggregate + 120, own, 6);
    aggregate[127] = 79; memcpy(aggregate + 128, regular + 26, 79);
    aggregate[138] = 2; /* second AWDL sequence */
    struct datagrams d = {0};
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_OK);
    assert(d.count == 2 && d.aggregate == 2 && d.long_header == 1);
    assert(d.sequence[0] == 1 && d.sequence[1] == 2);
    single.ipv6_size = 999;
    assert(pc_awdl_data_parse(aggregate, 207, &single) == PC_UNSUPPORTED && single.ipv6_size == 999);
    assert(pc_awdl_data_parse(aggregate, 112, &single) == PC_OK && single.aggregate);
    /* Validate the whole aggregate before releasing any datagrams. */
    for (size_t n = 113; n < 207; n++) {
        d.count = 0;
        assert(pc_awdl_data_visit(aggregate, n, datagram, &d) != PC_OK && d.count == 0);
    }
    aggregate[120] ^= 2;
    d.count = 0;
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_UNSUPPORTED && !d.count);
    aggregate[120] ^= 2; aggregate[114] ^= 2;
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_UNSUPPORTED && !d.count);
    aggregate[114] ^= 2; aggregate[126] = 0xff;
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_INVALID && !d.count);
    aggregate[126] = 0; aggregate[206] ^= 1; /* corrupt payload, not its IPv6 structure */
    assert(pc_awdl_data_visit(aggregate, 207, NULL, NULL) == PC_OK);
    aggregate[206] ^= 1; aggregate[156]++; /* corrupt second IPv6 length */
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_INVALID && !d.count);
    aggregate[156]--;
    aggregate[207] = 0;
    assert(pc_awdl_data_visit(aggregate, 208, datagram, &d) == PC_INVALID && !d.count);

    /* A foreign LLC member is skipped, but cannot conceal a malformed tail. */
    aggregate[40] = 0;
    assert(pc_awdl_data_visit(aggregate, 207, datagram, &d) == PC_OK && d.count == 1);
    aggregate[40] = 0xaa;
    /* Bound the CPU cost even for a syntactically valid large aggregate. */
    for (unsigned i = 0; i < 65; i++) {
        size_t h = 26 + 88 * i;
        memcpy(aggregate + h, peer, 6); memcpy(aggregate + h + 6, own, 6);
        aggregate[h + 12] = 0; aggregate[h + 13] = 72;
        memcpy(aggregate + h + 14, body, 72);
    }
    d = (struct datagrams){0};
    assert(pc_awdl_data_visit(aggregate, 26 + 64 * 88 - 2, datagram, &d) == PC_OK && d.count == 64);
    d.count = 0;
    assert(pc_awdl_data_visit(aggregate, 26 + 65 * 88 - 2, datagram, &d) == PC_UNSUPPORTED && !d.count);
}

struct observed { struct pc_awdl_sync sync; struct pc_awdl_channels channels; uint32_t self_metric; };
static void observe(uint8_t type, const uint8_t *p, size_t n, void *ctx) {
    struct observed *value = ctx;
    if (type == 4) {
        assert(n == 73 && p[9] == 0 && p[10] == 0x18 && p[11] == 16 && p[13] == 16);
        assert(p[34] == 1 && p[71] == 0 && p[72] == 0);
        for (unsigned i = 0; i < 16; i++)
            assert((p[39 + 2 * i] == 0 && p[40 + 2 * i] == 0) ||
                   (p[39 + 2 * i] == 0x2b && p[40 + 2 * i] == 6));
        assert(pc_awdl_sync_parse(p, n, &value->sync) == PC_OK);
    }
    if (type == 18) assert(pc_awdl_channels_parse(p, n, &value->channels) == PC_OK);
    if (type == 24) { assert(n == 40); value->self_metric = (uint32_t)p[24] | (uint32_t)p[25] << 8; }
    if (type == 12) {
        assert(n == 13);
        assert(p[0] == 0xc4 && (p[1] == 3 || p[1] == 7)); /* sink, channel role; bit 10: Solo Mode */
        assert(!memcmp(p + 2, "X0", 3) && p[5] == 1 && p[6] == 0);
        assert(!(p[0] & 0x20)); /* no dual-band claim */
    }
    if (type == 7) assert(n == 8 && p[2] == 0x20 && p[3] == 0x10 && p[5] == 0xff && p[6] == 0);
    if (type == 21) assert(n == 2 && p[0] == 0x34 && p[1] == 1);
}

void test_follow(void) {
    uint8_t own[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 5, 6, 7, 8, 9};
    uint8_t input[166] = {0}, output[400]; size_t written;
    input[0] = 0xd0; memcpy(input + 10, peer, 6);
    memcpy(input + 24, "\x7f\x00\x17\xf2\x08\x10\x03\x00", 8);
    input[40] = 4; input[41] = 33;
    input[43] = 6; input[44] = 32; input[46] = 6; input[48] = 16;
    memcpy(input + 64, peer, 6); input[70] = 4; input[72] = 2;
    input[76] = 24; input[77] = 40; memcpy(input + 79, peer, 6);
    input[99] = 0xfe; input[100] = 1; /* master metric 510 */
    input[119] = 18; input[120] = 41;
    uint8_t *peer_channels = input + 122;
    peer_channels[0] = 15; peer_channels[1] = 3; peer_channels[3] = 3;
    peer_channels[4] = peer_channels[5] = 255;
    for (unsigned i = 0; i < 16; i++) { peer_channels[6 + 2 * i] = 6; peer_channels[7 + 2 * i] = 81; }
    const uint8_t countdowns[] = {64,63,61,49,48,32,16,1};
    const uint8_t common_left[] = {16,15,13,1,0,0,0,0};
    for (size_t i = 0; i < sizeof(countdowns); i++) {
        input[44] = countdowns[i];
        input[72] = (uint8_t)((64 - countdowns[i]) / 16);
        assert(pc_awdl_follow_build(own, input, 163, 17, 0, 3, output, sizeof(output), &written) == PC_OK);
        assert(output[58] == common_left[i] && output[59] == 0);
    }
    peer_channels[6] = peer_channels[7] = 0; input[44] = 61; input[72] = 0;
    assert(pc_awdl_follow_build(own, input, 163, 17, 0, 3, output, sizeof(output), &written) == PC_OK);
    assert(output[58] == 13 && output[59] == 0); /* own radio remains on 6 */
    peer_channels[6] = 6; peer_channels[7] = 81; input[44] = 32; input[72] = 2;
    assert(pc_awdl_follow_build(own, input, 163, 17, 0x11223344, 3, output, sizeof(output), &written) == PC_OK);
    struct pc_awdl a; struct observed observed = {0};
    assert(written <= 300 && pc_awdl_parse(output, written, &a, observe, &observed) == PC_OK);
    assert(a.subtype == 3 && a.phy_time == 0x11223344 && !memcmp(a.source, own, 6));
    const uint8_t expected_tags[] = {4, 5, 18, 24, 6, 7, 16, 12, 21};
    size_t cursor = 40;
    for (size_t i = 0; i < sizeof(expected_tags); i++) {
        assert(cursor + 3 <= written && output[cursor] == expected_tags[i]);
        size_t length = output[cursor + 1] + ((size_t)output[cursor + 2] << 8);
        assert(length <= written - cursor - 3);
        if (output[cursor] == 7) assert(length == 8 && output[cursor + 3 + 5] == 0xff);
        cursor += 3 + length;
    }
    assert(cursor == written);
    assert(observed.self_metric == 60 && observed.sync.aw_period_tu == 16);
    assert(!memcmp(observed.sync.master, peer, 6) && observed.channels.count == 16);
    for (unsigned i = 0; i < 16; i++)
        assert(observed.channels.number[i] == 6 && observed.channels.operating_class[i] == 81);
    /* Gaps: 5 slots on, 3 off, in both sequences; the first entry stays present. */
    pc_awdl_follow_set_profile(1, 1);
    uint8_t single[400]; size_t single_n;
    assert(pc_awdl_follow_build(own, input, 163, 17, 0x11223344, 3, single, sizeof(single), &single_n) == PC_OK);
    size_t single_tag = 40;
    while (single[single_tag] != 18) single_tag += 3 + single[single_tag + 1] + ((size_t)single[single_tag + 2] << 8);
    for (unsigned i = 0; i < 16; i++) assert(single[single_tag + 3 + 6 + 2 * i] == (i % 8 == 7 ? 0 : 6));
    pc_awdl_follow_set_profile(3, 0);
    uint8_t gapped[400]; size_t gapped_n; struct observed gap_seen = {0};
    assert(pc_awdl_follow_build(own, input, 163, 17, 0x11223344, 3, gapped, sizeof(gapped), &gapped_n) == PC_OK);
    pc_awdl_follow_set_profile(0, 1);
    size_t tag = 40; const uint8_t *timing_tag = NULL, *channel_value = NULL;
    while (tag + 3 <= gapped_n) {
        size_t size = gapped[tag + 1] + ((size_t)gapped[tag + 2] << 8);
        if (gapped[tag] == 4) timing_tag = gapped + tag + 3;
        if (gapped[tag] == 18) channel_value = gapped + tag + 3;
        if (gapped[tag] == 12) assert(!(gapped[tag + 4] & 0x04)); /* no Solo Mode */
        tag += 3 + size;
    }
    assert(timing_tag && channel_value);
    for (unsigned i = 0; i < 16; i++) {
        unsigned expected = i % 8 >= 5 ? 0 : 6;
        assert(channel_value[6 + 2 * i] == expected && timing_tag[40 + 2 * i] == expected);
    }
    assert(pc_awdl_parse(gapped, gapped_n, &a, observe, &gap_seen) == PC_OK && gap_seen.channels.count == 16);
    assert(pc_awdl_data_window(output, written, 10000) == PC_OK);
    assert(pc_awdl_data_window(output, written, 30000) == PC_OTHER);
    output[44] = 64;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER); /* leading guard */
    assert(pc_awdl_data_window(output, written, 5000) == PC_OK);
    output[44] = 2;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER); /* trailing guard */
    output[44] = 32;
    size_t channel_tag = 40;
    while (output[channel_tag] != 18)
        channel_tag += 3 + output[channel_tag + 1] + ((size_t)output[channel_tag + 2] << 8);
    uint8_t *channel = output + channel_tag + 3;
    channel[6] = 0;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER); /* PSF is not data availability */
    channel[6] = 149;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER);
    /* Advance the AW counter across the 16-bit wrap; select the last entry. */
    output[72] = output[73] = 255;
    assert(pc_awdl_data_window(output, written, 0) == PC_OK);
    channel[36] = 0;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER);
    channel[36] = channel[6] = 6;
    channel[3] = 1;
    assert(pc_awdl_data_window(output, written, 0) == PC_UNSUPPORTED);
    channel[3] = 3;
    /* PHY minus target is 7 us across the peer's 32-bit clock wrap. */
    memset(output + 32, 0, 8); output[32] = 3;
    memset(output + 36, 255, 4); output[36] = 252;
    assert(pc_awdl_data_window(output, written, 0) == PC_OK);
    output[32] = 0; memset(output + 36, 0, 4); output[34] = 2;
    assert(pc_awdl_data_window(output, written, 0) == PC_OTHER);
    assert(pc_awdl_data_window(output, 40, 0) == PC_INVALID);
    assert(pc_awdl_follow_build(own, input, 163, 18, 0, 0, output, sizeof(output), &written) == PC_OK);
    assert(pc_awdl_parse(output, written, &a, NULL, NULL) == PC_OK && a.subtype == 0 && a.tags == 7);
    assert(pc_awdl_follow_build(peer, input, 163, 17, 0, 3, output, sizeof(output), &written) == PC_UNSUPPORTED && written == 0);
    /* Sparse mixed-band peer: our fixed-channel radio remains available on
     * 6 in every slot. Never inherit foreign 5 GHz capabilities or absences. */
    memset(peer_channels + 6, 0, 32);
    peer_channels[6] = 3; peer_channels[7] = 81; /* infrastructure channel */
    peer_channels[8] = 149; peer_channels[9] = 124;
    peer_channels[12] = peer_channels[36] = 6;
    peer_channels[13] = peer_channels[37] = 81;
    peer_channels[14] = 6; peer_channels[15] = 115; /* wrong operating class */
    assert(pc_awdl_follow_build(own, input, 163, 19, 0, 3, output, sizeof(output), &written) == PC_OK);
    observed = (struct observed){0};
    assert(pc_awdl_parse(output, written, &a, observe, &observed) == PC_OK);
    for (unsigned i = 0; i < 16; i++) {
        assert(observed.channels.number[i] == 6);
        assert(observed.channels.operating_class[i] == 81);
        assert(output[82 + 2 * i] == 0x2b);
        assert(output[83 + 2 * i] == 6);
    }
    assert(pc_awdl_follow_build(own, input, 119, 19, 0, 3, output, sizeof(output), &written) == PC_INVALID && !written);
    peer_channels[3] = 1;
    assert(pc_awdl_follow_build(own, input, 163, 19, 0, 3, output, sizeof(output), &written) == PC_UNSUPPORTED && !written);
    peer_channels[3] = 3;
    /* Observed native one-hop hierarchy: Sync clock owner is the peer,
     * Election root and parent identify the same other node. */
    uint8_t root[6]={2,9,8,7,6,5};
    memcpy(input+79,root,6);memcpy(input+85,root,6);input[95]=1;
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_OK);
    size_t election_tag=40;
    while(output[election_tag]!=24) election_tag+=3+output[election_tag+1]+((size_t)output[election_tag+2]<<8);
    assert(!memcmp(output+election_tag+3,root,6));
    assert(!memcmp(output+election_tag+9,peer,6));
    assert(output[election_tag+19]==2); /* our distance to root */
    /* Several Apple devices nearby: deeper tree, parent differs from root (r170). */
    input[85]^=2;input[95]=2;
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_OK);
    assert(output[election_tag+19]==3);
    input[95]=8;
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_UNSUPPORTED);
    input[95]=2;memcpy(input+85,own,6);
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_UNSUPPORTED);
    memcpy(input+85,root,6);
    input[95]=1;memcpy(input+79,own,6);memcpy(input+85,own,6);
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_UNSUPPORTED);
    memcpy(input+79,root,6);memcpy(input+85,root,6);input[79]|=1;input[85]|=1;
    assert(pc_awdl_follow_build(own,input,163,19,0,3,output,sizeof(output),&written)==PC_UNSUPPORTED);
    memcpy(input+79,peer,6);memset(input+85,0,6);input[95]=0;
    input[48] = 8;
    assert(pc_awdl_follow_build(own, input, 163, 17, 0, 3, output, sizeof(output), &written) == PC_UNSUPPORTED);
    input[48] = 16; input[163] = 4;
    assert(pc_awdl_follow_build(own, input, 166, 17, 0, 3, output, sizeof(output), &written) == PC_INVALID);
    assert(pc_awdl_follow_build(own, input, 163, 17, 0, 3, output, 200, &written) == PC_INVALID);
}

void test_mdns(void) {
    const uint8_t own[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {0xb2, 0x51, 0xf4, 0x14, 0x31, 0x54};
    uint8_t expected[94], request[94], reply[127], frame[192];
    fixture("60000000003611fffe80000000000000000102fffe030405fe80000000000000b051f4fffe143154d23414e90036f951123400000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001", expected, 94);
    fixture("60000000005711fffe80000000000000b051f4fffe143154fe80000000000000000102fffe03040514e9d23400575a16123484000001000100000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001c00c000c00010000000a0015085f616972706c6179045f746370056c6f63616c00", reply, 127);
    assert(pc_mdns_build(own, peer, 0x1234, request) == PC_OK && !memcmp(request, expected, 94));
    uint16_t answers;
    assert(pc_mdns_reply(reply, 127, own, peer, 0x1234, &answers) == PC_OK && answers == 1);
    assert(pc_mdns_reply(reply, 127, own, peer, 0x1235, &answers) == PC_OTHER && answers == 0);
    size_t written;
    assert(pc_awdl_data_build(own, peer, 1, request, 94, frame, sizeof(frame), &written) == PC_OK && written == 136);
    for (size_t n = 0; n < 127; n++)
        assert(pc_mdns_reply(reply, n, own, peer, 0x1234, &answers) == PC_INVALID);
    /* Cyclic owner-name pointer, with independently recalculated checksum. */
    reply[95] = 46; reply[46] = 0x59; reply[47] = 0xf4;
    assert(pc_mdns_reply(reply, 127, own, peer, 0x1234, &answers) == PC_INVALID);
    reply[95] = 12; reply[46] = 0x5a; reply[47] = 0x15; reply[105] = 22;
    assert(pc_mdns_reply(reply, 127, own, peer, 0x1234, &answers) == PC_INVALID); /* overlong RDATA */
    reply[105] = 21; reply[46] = 0; reply[47] = 0;
    assert(pc_mdns_reply(reply, 127, own, peer, 0x1234, &answers) == PC_INVALID);
}

void test_mdns_group(void) {
    const uint8_t own[6] = {2,1,2,3,4,5}, peer[6] = {0xb2,0x51,0xf4,0x14,0x31,0x54};
    uint8_t query[88], expected[88], reply[101], compressed[120]; uint16_t answers;
    /* Independent Python struct/ipaddress/pseudoheader vectors. */
    fixture("60000000003011fffe80000000000000000102fffe030405ff0200000000000000000000000000fb14e914e90030941d0000000000010000000000000b5f70696361737464696167045f756470056c6f63616c00000c0001", expected, 88);
    fixture("60000000003d11fffe80000000000000b051f4fffe143154ff0200000000000000000000000000fb14e914e9003d55a40000840000000001000000000b5f70696361737464696167045f756470056c6f63616c00000c00010000001e00070454657374c00c", reply, 101);
    fixture("60000000005011fffe80000000000000b051f4fffe143154ff0200000000000000000000000000fb14e914e900508ed20000840000000002000000000b5f70696361737464696167045f756470056c6f63616c00000c00010000001e00070454657374c00cc00c000c00010000001e00070454657374c00c", compressed, 120);
    assert(pc_mdns_group_build(own, query) == PC_OK && !memcmp(query, expected, 88));
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_OK && answers == 1);
    assert(pc_mdns_group_reply(compressed, 120, own, peer, &answers) == PC_OK && answers == 2);
    assert(pc_mdns_group_reply(reply, 101, peer, own, &answers) == PC_OTHER && !answers);
    for (size_t n = 0; n < 101; n++)
        assert(pc_mdns_group_reply(reply, n, own, peer, &answers) == PC_INVALID && !answers);
    reply[7] = 64;
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_INVALID);
    reply[7] = 255; reply[100] = 51; reply[47] = 0x7d; /* self-referential RDATA name */
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_INVALID);
    reply[100] = 12; reply[47] = 0xa3; reply[93] = 8; /* RDATA exceeds datagram */
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_INVALID);
    reply[93] = 7; reply[61] = 'x'; reply[47] = 0x8b; /* unrelated service owner */
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_OTHER && !answers);
    reply[46] = reply[47] = 0;
    assert(pc_mdns_group_reply(reply, 101, own, peer, &answers) == PC_INVALID);
}

void test_service(void) {
    const uint8_t source[6] = {2,1,2,3,4,5}, mac[6] = {2,5,6,7,8,9};
    uint8_t token[16], guarded[423], expected[421], frame[576]; size_t written;
    for (unsigned i = 0; i < 16; i++) token[i] = (uint8_t)i;
    memset(guarded, 0xa5, sizeof(guarded));
    /* Independent DNS label/RR encoding and IPv6 checksum fixture. */
    fixture(
        "60000000017d11fffe80000000000000000102fffe030405ff0200000000000000000000000000fb14e914e9017dc7620000"
        "840000000001000000030b5f70696361737464696167045f756470056c6f63616c00000c00010000000f00442b5069436173"
        "742d6c61622d30303031303230333034303530363037303830393061306230633064306530660b5f70696361737464696167"
        "045f756470056c6f63616c002b5069436173742d6c61622d3030303130323033303430353036303730383039306130623063"
        "3064306530660b5f70696361737464696167045f756470056c6f63616c00002180010000000f001400000000908806706963"
        "617374056c6f63616c002b5069436173742d6c61622d30303031303230333034303530363037303830393061306230633064"
        "306530660b5f70696361737464696167045f756470056c6f63616c00001080010000000f002b03763d3126746f6b656e3d30"
        "3030313032303330343035303630373038303930613062306330643065306606706963617374056c6f63616c00001c800100"
        "00000f0010fe80000000000000000102fffe030405", expected, 421);
    assert(pc_service_build(source, token, guarded + 1) == PC_OK);
    assert(guarded[0] == 0xa5 && guarded[422] == 0xa5);
    assert(!memcmp(guarded + 1, expected, 421));
    uint16_t answers;
    assert(pc_mdns_group_reply(guarded + 1, 421, mac, source, &answers) == PC_OK && answers == 1);
    assert(pc_awdl_data_build(source, (const uint8_t[]){0x33,0x33,0,0,0,0xfb}, 1,
                              guarded + 1, 421, frame, sizeof(frame), &written) == PC_OK && written == 463);
    assert(pc_service_build((const uint8_t[]){1,1,2,3,4,5}, token, guarded + 1) == PC_INVALID);
    assert(pc_service_build(source, NULL, guarded + 1) == PC_INVALID);
    assert(pc_service_build(source, token, NULL) == PC_INVALID);
    uint8_t airplay[1282], pk[32]={9}; size_t size;
    memset(airplay,0xa7,sizeof(airplay));
    assert(pc_airplay_service_build(source,token,pk,airplay+1,1280,&size)==PC_OK);
    assert(size>421 && size<1280 && airplay[0]==0xa7 && airplay[size+1]==0xa7);
    const char pairing_field[]="\x27" "pi=09000000-0000-4000-8000-000000000000";
    unsigned pairing_fields=0;
    for (size_t i=1;i+sizeof(pairing_field)-1<=size+1;i++)
        if (!memcmp(airplay+i,pairing_field,sizeof(pairing_field)-1)) pairing_fields++;
    /* The native laboratory repeats the identity for the RAOP companion. */
    assert(pairing_fields==2);
    size_t capacity=size-1;
    memset(airplay,0xa7,sizeof(airplay));
    assert(pc_airplay_service_build(source,token,pk,airplay+1,capacity,&size)==PC_INVALID && !size);
    for (size_t i=0;i<sizeof(airplay);i++) assert(airplay[i]==0xa7);
    assert(pc_airplay_p2p_service_build(source,token,pk,airplay+1,1280,&size)==PC_OK);
    capacity=size-1;
    memset(airplay,0xa7,sizeof(airplay));
    assert(pc_airplay_p2p_service_build(source,token,pk,airplay+1,capacity,&size)==PC_INVALID && !size);
    for (size_t i=0;i<sizeof(airplay);i++) assert(airplay[i]==0xa7);
}

void test_udp(void) {
    const uint8_t own[6] = {2,1,2,3,4,5}, peer[6] = {2,5,6,7,8,9};
    uint8_t token[16], expected[84], reply[84], request[84], frame[192];
    for (unsigned i = 0; i < 16; i++) token[i] = (uint8_t)i;
    fixture("60000000002c1140fe80000000000000000102fffe030405fe80000000000000000506fffe070809d23490d5002ce1c7000102030405060708090a0b0c0d0e0f12340007506943617374205544502070726f6265", expected, 84);
    fixture("60000000002c1140fe80000000000000000506fffe070809fe80000000000000000102fffe03040590d5d234002ce1c7000102030405060708090a0b0c0d0e0f12340007506943617374205544502070726f6265", reply, 84);
    assert(pc_udp_build(own, peer, 37077, 0x1234, 7, token, request) == PC_OK);
    assert(!memcmp(request, expected, 84));
    assert(pc_udp_reply(reply, 84, own, peer, 37077, 0x1234, 7, token) == PC_OK);
    assert(pc_udp_reply(reply, 84, own, peer, 37078, 0x1234, 7, token) == PC_OTHER);
    assert(pc_udp_reply(reply, 84, own, peer, 37077, 0x1234, 8, token) == PC_OTHER);
    token[0] ^= 1;
    assert(pc_udp_reply(reply, 84, own, peer, 37077, 0x1234, 7, token) == PC_OTHER);
    token[0] ^= 1;
    for (size_t n = 0; n < 84; n++) assert(pc_udp_reply(reply, n, own, peer, 37077, 0x1234, 7, token) == PC_INVALID);
    reply[83] ^= 1;
    assert(pc_udp_reply(reply, 84, own, peer, 37077, 0x1234, 7, token) == PC_INVALID);
    reply[83] ^= 1; reply[46] = reply[47] = 0;
    assert(pc_udp_reply(reply, 84, own, peer, 37077, 0x1234, 7, token) == PC_INVALID);
    assert(pc_udp_build(own, own, 37077, 1, 1, token, request) == PC_INVALID);
    assert(pc_udp_build(own, peer, 1023, 1, 1, token, request) == PC_INVALID);
    size_t written;
    assert(pc_awdl_data_build(own, peer, 7, request, 84, frame, sizeof(frame), &written) == PC_OK);
    assert(frame[24] == 0 && frame[25] == 0); /* native UDP best-effort TID */
    struct pc_awdl_data parsed;
    assert(pc_awdl_data_parse(frame, written, &parsed) == PC_OK);
    assert(parsed.ipv6_size == 84 && !memcmp(parsed.ipv6, expected, 84));
    assert(pc_awdl_data_build_legacy(own, peer, 7, request, 84, frame, sizeof(frame), &written) == PC_OK);
    assert(written == 124 && frame[0] == 0x08 && frame[24] == 0xaa);
    assert(pc_awdl_data_parse(frame, written, &parsed) == PC_OK);
    assert(parsed.sequence == 7 && parsed.ipv6_size == 84 && !memcmp(parsed.ipv6, expected, 84));
    /* Restricted incoming native UDP diagnostic; verify the swapped response
     * through the independent reply validator, plus hostile input rejection. */
    assert(pc_udp_build(peer, own, 37000, 0x5043, 1, token, request) == PC_OK);
    assert(pc_udp_respond(request, 84, own, peer, 37000, token, reply) == PC_OK);
    assert(pc_udp_reply(reply, 84, peer, own, 37000, 0x5043, 1, token) == PC_OK);
    assert(pc_udp_respond(request, 84, own, peer, 37001, token, reply) == PC_OTHER);
    assert(pc_udp_respond(request, 84, peer, own, 37000, token, reply) == PC_OTHER);
    token[0] ^= 1;
    assert(pc_udp_respond(request, 84, own, peer, 37000, token, reply) == PC_OTHER);
    token[0] ^= 1;
    for (size_t n = 0; n < 84; n++) assert(pc_udp_respond(request, n, own, peer, 37000, token, reply) == PC_INVALID);
    request[83] ^= 1;
    assert(pc_udp_respond(request, 84, own, peer, 37000, token, reply) == PC_INVALID);
    assert(pc_udp_build(peer, own, 37000, 0x5043, 4, token, request) == PC_OK);
    assert(pc_udp_respond(request, 84, own, peer, 37000, token, reply) == PC_OTHER);
    assert(pc_udp_build(peer, own, 37000, 0x5043, 3, token, request) == PC_OK);
    assert(pc_udp_respond(request, 84, own, peer, 37000, token, request) == PC_OK);
    assert(pc_udp_reply(request, 84, peer, own, 37000, 0x5043, 3, token) == PC_OK);
}

void test_neighbor(void) {
    const uint8_t own[6] = {2,0x50,0x43,0,0,1}, peer[6] = {2,0x50,0x43,0,0,2};
    uint8_t request[80], expected[72], reply[80]; size_t size;
    fixture("6000000000203afffe80000000000000005043fffe000002ff0200000000000000000001ff0000018700b2a600000000fe80000000000000005043fffe0000010101025043000002", request, 72);
    fixture("6000000000203afffe80000000000000005043fffe000001fe80000000000000005043fffe00000288000ddb60000000fe80000000000000005043fffe0000010201025043000001", expected, 72);
    assert(pc_neighbor_build(peer, own, reply) == PC_OK && !memcmp(reply, request, 72));
    assert(pc_neighbor_reply(expected, 72, peer, own) == PC_OK);
    assert(pc_neighbor_reply(expected, 72, own, peer) == PC_OTHER);
    assert(pc_neighbor_build(own, own, reply) == PC_INVALID);
    assert(pc_neighbor_respond(request, 72, own, peer, reply, sizeof(reply), &size) == PC_OK);
    assert(size == 72 && !memcmp(reply, expected, 72));
    memset(reply, 0xaa, sizeof(reply));
    assert(pc_neighbor_respond(request, 72, own, peer, reply, 71, &size) == PC_INVALID && !size && reply[0] == 0xaa);
    for (size_t n = 0; n < 72; n++)
        assert(pc_neighbor_respond(request, n, own, peer, reply, sizeof(reply), &size) != PC_OK && !size && reply[0] == 0xaa);
    request[7] = 254;
    assert(pc_neighbor_respond(request, 72, own, peer, reply, sizeof(reply), &size) == PC_INVALID && !size && reply[0] == 0xaa);
    request[7] = 255; request[71] ^= 1;
    assert(pc_neighbor_respond(request, 72, own, peer, reply, sizeof(reply), &size) == PC_INVALID && !size && reply[0] == 0xaa);
    request[71] ^= 1;
    assert(pc_neighbor_respond(request, 72, peer, own, reply, sizeof(reply), &size) == PC_OTHER && !size);
    assert(pc_neighbor_respond(request, 72, own, own, reply, sizeof(reply), &size) == PC_INVALID && !size);
    assert(pc_neighbor_respond(request, 72, own, peer, request, sizeof(request), &size) == PC_OK);
    assert(size == 72 && !memcmp(request, expected, 72));
}

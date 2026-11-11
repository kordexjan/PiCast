#include "picast.h"
#include <string.h>
#include <stdio.h>

static void little(uint8_t *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8 * i));
}

int pc_pcap_header(uint8_t out[24], uint32_t linktype) {
    if (!out || (linktype != 105 && linktype != 127)) return PC_INVALID;
    memset(out, 0, 24);
    little(out, 0xa1b2c3d4);
    out[4] = 2; out[6] = 4;
    little(out + 16, 65535);
    little(out + 20, linktype);
    return PC_OK;
}

int pc_pcap_record(uint8_t out[16], uint32_t seconds, uint32_t microseconds, size_t length) {
    if (!out || microseconds >= 1000000 || length > 65535) return PC_INVALID;
    little(out, seconds); little(out + 4, microseconds);
    little(out + 8, (uint32_t)length); little(out + 12, (uint32_t)length);
    return PC_OK;
}

static uint32_t word(const uint8_t *p, int le) {
    uint32_t v = 0;
    for (int j = 0; j < 4; j++) v |= (uint32_t)p[le ? j : 3 - j] << (8 * j);
    return v;
}

int pc_pcap_walk(const char *path, pc_packet_fn callback, void *ctx) {
    if (!path) return PC_INVALID;
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return PC_INVALID; }
    int result = PC_INVALID, le, nano;
    uint8_t header[24], record[16], packet[65535];
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) goto done;
    if (!memcmp(header, "\xd4\xc3\xb2\xa1", 4)) { le = 1; nano = 0; }
    else if (!memcmp(header, "\x4d\x3c\xb2\xa1", 4)) { le = 1; nano = 1; }
    else if (!memcmp(header, "\xa1\xb2\xc3\xd4", 4)) { le = 0; nano = 0; }
    else if (!memcmp(header, "\xa1\xb2\x3c\x4d", 4)) { le = 0; nano = 1; }
    else goto done;
    if ((le ? header[4] != 2 || header[5] || header[6] != 4 || header[7] :
              header[4] || header[5] != 2 || header[6] || header[7] != 4)) goto done;
    uint32_t snap = word(header + 16, le), link = word(header + 20, le);
    if (!snap || snap > sizeof(packet) || (link != 105 && link != 127)) goto done;
    for (;;) {
        size_t got = fread(record, 1, sizeof(record), f);
        if (!got && !ferror(f)) { result = PC_OK; break; }
        if (got != sizeof(record)) break;
        uint32_t size = word(record + 8, le), original = word(record + 12, le), fraction = word(record + 4, le);
        if (size > snap || size > original || fraction >= (nano ? 1000000000U : 1000000U) ||
            fread(packet, 1, size, f) != size) break;
        struct pc_pcap_packet view = {.data = packet, .size = size, .original_size = original,
            .linktype = link, .timestamp_us = (uint64_t)word(record, le) * 1000000 + fraction / (nano ? 1000 : 1)};
        if (callback) {
            int rc = callback(&view, ctx);
            if (rc != PC_OK) { result = rc; break; }
        }
    }
done:
    fclose(f);
    return result;
}

#include "picast.h"
#include <string.h>

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | (uint16_t)p[1] << 8);
}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int pc_awdl_sync_parse(const uint8_t *p, size_t n, struct pc_awdl_sync *out) {
    if (!p || !out || n < 33) return PC_INVALID;
    struct pc_awdl_sync value = {0};
    value.tx_channel = p[0]; value.tx_counter = le16(p + 1);
    value.master_channel = p[3]; value.guard = p[4];
    value.aw_period_tu = le16(p + 5); value.action_period_tu = le16(p + 7);
    memcpy(value.master, p + 21, 6);
    value.presence = p[27]; value.aw_counter = le16(p + 29);
    *out = value;
    return PC_OK;
}

int pc_awdl_channels_parse(const uint8_t *p, size_t n, struct pc_awdl_channels *out) {
    if (!p || !out || n < 6) return PC_INVALID;
    if (p[1] != 3) return PC_UNSUPPORTED;
    size_t count = (size_t)p[0] + 1;
    if (n - 6 < count * 2) return PC_INVALID;
    struct pc_awdl_channels value = {0};
    value.count = (uint16_t)count; value.duplicate = p[2];
    value.step = p[3]; value.fill = le16(p + 4);
    for (size_t i = 0; i < count; i++) {
        value.number[i] = p[6 + 2 * i]; value.operating_class[i] = p[7 + 2 * i];
    }
    *out = value;
    return PC_OK;
}

int pc_netlink_attr(const uint8_t *p, size_t n, uint16_t type,
                    const uint8_t **value, size_t *size) {
    if ((!p && n) || !value || !size) return PC_INVALID;
    const uint8_t *found = NULL; size_t length = 0;
    while (n) {
        if (n < 4) return PC_INVALID;
        uint16_t total, kind;
        memcpy(&total, p, sizeof(total)); memcpy(&kind, p + 2, sizeof(kind));
        if (total < 4 || total > n) return PC_INVALID;
        if ((kind & 0x3fffU) == type) { found = p + 4; length = total - 4; }
        size_t step = ((size_t)total + 3) & ~(size_t)3;
        if (step > n) return PC_INVALID;
        p += step; n -= step;
    }
    *value = found; *size = length;
    return found ? PC_OK : PC_OTHER;
}

int pc_awdl_parse(const uint8_t *p, size_t n, struct pc_awdl *out,
                  pc_item_fn fn, void *ctx) {
    struct pc_awdl result = {0};
    if (!out || (!p && n)) return PC_INVALID;
    if (n < 2) return PC_INVALID;
    /* Version=0, management action subtype=13. No protected/fragmented frames. */
    if (p[0] != 0xd0) return PC_OTHER;
    if (n < 24) return PC_INVALID;
    if ((p[1] & 0xc7) || (p[22] & 0x0f)) return PC_UNSUPPORTED;
    if (n < 28) return PC_INVALID;
    const uint8_t prefix[] = {0x7f, 0x00, 0x17, 0xf2};
    if (memcmp(p + 24, prefix, sizeof(prefix))) return PC_OTHER;
    if (n < 40) return PC_INVALID;
    if (p[28] != 0x08) return PC_OTHER;
    /* Known fixed action-body layout; do not guess layouts of future versions. */
    if (p[29] != 0x10) return PC_UNSUPPORTED;
    memcpy(result.source, p + 10, 6);
    result.version = p[29]; result.subtype = p[30];
    result.phy_time = le32(p + 32); result.target_time = le32(p + 36);
    size_t pos = 40;
    while (pos < n) {
        if (n - pos < 3) return PC_INVALID;
        size_t length = le16(p + pos + 1);
        pos += 3;
        if (length > n - pos) return PC_INVALID;
        result.tags++;
        pos += length;
    }
    *out = result;
    if (fn) for (pos = 40; pos < n;) {
        size_t length = le16(p + pos + 1);
        fn(p[pos], p + pos + 3, length, ctx);
        pos += 3 + length;
    }
    return PC_OK;
}

static int ble_walk(const uint8_t *p, size_t n, struct pc_ble *r,
                    pc_item_fn fn, void *ctx) {
    size_t pos = 0;
    while (pos < n) {
        size_t length = p[pos++];
        if (!length) {
            /* AD terminator; only zero padding may follow. */
            while (pos < n) if (p[pos++]) return PC_INVALID;
            break;
        }
        if (length > n - pos) return PC_INVALID;
        size_t end = pos + length;
        if (p[pos] == 0xff) {
            if (length < 3) return PC_INVALID;
            if (p[pos + 1] == 0x4c && p[pos + 2] == 0x00) {
                size_t item = pos + 3;
                r->apple_records++;
                while (item < end) {
                    if (end - item < 2) return PC_INVALID;
                    uint8_t type = p[item++];
                    size_t count = p[item++];
                    if (count > end - item) return PC_INVALID;
                    if (type == 0x09) r->airplay_records++;
                    if (type == 0x16) r->peer_records++;
                    if (fn) fn(type, p + item, count, ctx);
                    item += count;
                }
            }
        }
        pos = end;
    }
    return PC_OK;
}

int pc_ble_parse(const uint8_t *p, size_t n, struct pc_ble *out,
                 pc_item_fn fn, void *ctx) {
    struct pc_ble result = {0};
    if (!out || (!p && n)) return PC_INVALID;
    if (ble_walk(p, n, &result, NULL, NULL) != PC_OK) return PC_INVALID;
    *out = result;
    if (fn) {
        struct pc_ble ignored = {0};
        (void)ble_walk(p, n, &ignored, fn, ctx);
    }
    return PC_OK;
}

/* Some SDIO monitor deliveries retain up to 16 zero DMA padding bytes
 * after the on-wire FCS. Remove padding only when the preceding FCS verifies;
 * never infer a shorter packet from a protocol payload length alone. */
static uint32_t frame_crc32(const uint8_t *p, size_t n) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}
static size_t frame_fcs_body(const uint8_t *p, size_t n) {
    size_t body = n - 4;
    if (frame_crc32(p, body) == le32(p + body)) return body;
    for (size_t pad = 1; pad <= 16 && pad <= n - 4; pad++) {
        if (p[n - pad]) break;
        size_t candidate = n - pad - 4;
        if (candidate >= 24 && frame_crc32(p, candidate) == le32(p + candidate)) return candidate;
    }
    return body;
}

int pc_radiotap_parse(const uint8_t *p, size_t n, struct pc_radiotap_view *out) {
    struct pc_radiotap_view view = {0};
    if (!out || !p || n < 8) return PC_INVALID;
    if (p[0] != 0) return PC_UNSUPPORTED;
    size_t hdr = le16(p + 2), fields = 8;
    if (hdr < 8 || hdr > n) return PC_INVALID;
    uint32_t first = le32(p + 4), present = first;
    while (present & 0x80000000U) {
        if (fields > hdr || hdr - fields < 4) return PC_INVALID;
        present = le32(p + fields);
        fields += 4;
    }
    if (first & 1) {
        fields = (fields + 7) & ~(size_t)7;
        if (fields > hdr || hdr - fields < 8) return PC_INVALID;
        view.tsft_us = (uint64_t)le32(p + fields) | (uint64_t)le32(p + fields + 4) << 32;
        view.has_tsft = 1;
        fields += 8;
    }
    size_t body = n - hdr;
    if (first & 2) {
        if (fields >= hdr) return PC_INVALID;
        uint8_t flags = p[fields];
        view.flags = flags;
        if (flags & 0x40) return PC_INVALID;
        if (flags & 0x10) {
            if (body < 4) return PC_INVALID;
            body = frame_fcs_body(p + hdr, body);
        }
    }
    view.frame = p + hdr; view.frame_size = body;
    *out = view;
    return PC_OK;
}

int pc_radiotap(const uint8_t *p, size_t n, const uint8_t **frame, size_t *len) {
    if (!frame || !len) return PC_INVALID;
    struct pc_radiotap_view view;
    int result = pc_radiotap_parse(p, n, &view);
    if (result != PC_OK) return result;
    *frame = view.frame; *len = view.frame_size;
    return PC_OK;
}

int pc_ble_reports(const uint8_t *p, size_t n, pc_report_fn fn, void *ctx) {
    if (!p || n < 3) return PC_INVALID;
    if (p[0] != 0x04 || p[1] != 0x3e) return PC_OTHER;
    if ((size_t)p[2] != n - 3 || n < 5) return PC_INVALID;
    if (p[3] != 0x02) return PC_UNSUPPORTED;
    size_t pos = 5;
    for (unsigned i = 0; i < p[4]; i++) {
        if (n - pos < 10) return PC_INVALID;
        size_t length = p[pos + 8];
        if (length > 31 || length > n - pos - 10) return PC_INVALID;
        pos += 10 + length;
    }
    if (pos != n) return PC_INVALID;
    if (fn) for (pos = 5; pos < n;) {
        size_t length = p[pos + 8];
        unsigned raw = p[pos + 9 + length];
        int rssi = raw < 128 ? (int)raw : (int)raw - 256;
        fn(p + pos + 9, length, rssi, ctx);
        pos += 10 + length;
    }
    return PC_OK;
}

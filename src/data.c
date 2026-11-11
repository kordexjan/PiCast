#include "picast.h"
#include "picast_config.h"
#include "picast_identity.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const uint8_t bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
static const uint8_t snap[8] = {0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0};
static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static void be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static int unicast(const uint8_t *p) {
    static const uint8_t zero[6];
    return p && !(p[0] & 1) && memcmp(p, zero, 6);
}
static int ipv6_valid(const uint8_t *p, size_t n) {
    return p && n >= 40 && n <= 1500 && (p[0] >> 4) == 6 && (size_t)be16(p + 4) == n - 40;
}

void pc_linklocal(const uint8_t mac[6], uint8_t address[16]) {
    memset(address, 0, 16); address[0] = 0xfe; address[1] = 0x80;
    memcpy(address + 8, mac, 3); address[8] ^= 2;
    address[11] = 0xff; address[12] = 0xfe;
    memcpy(address + 13, mac + 3, 3);
}

/* Independent bounded decoding from the wire format; no third-party parser
 * implementation. References and conservative limits: docs/DATA_FORMAT.md. */
static int msdu(const uint8_t *p, size_t n, struct pc_awdl_data *out) {
    if (n < 8) return PC_INVALID;
    if (memcmp(p, snap, 8)) return PC_OTHER;
    p += 8; n -= 8;
    if (n < 8) return PC_INVALID;
    if (p[0] != 3 || p[1] != 4) return PC_UNSUPPORTED;
    size_t h = 4;
    out->long_header = 0;
    if (p[h] == 3) {
        out->long_header = 1;
        /* First marker, optional short-length TLVs, then closing marker.
         * Marker values and unknown TLVs are opaque, never interpreted. */
        size_t length = 2U + p[h + 1];
        if (length > n - h) return PC_INVALID;
        h += length;
        unsigned tags = 0;
        for (;;) {
            if (n - h < 2) return PC_INVALID;
            length = 2U + p[h + 1];
            if (length > n - h) return PC_INVALID;
            int closing = p[h] == 3;
            h += length;
            if (closing) break;
            if (++tags > 64) return PC_UNSUPPORTED;
        }
    } else {
        if (p[h] || p[h + 1]) return PC_UNSUPPORTED;
        h += 2;
    }
    if (n - h < 2) return PC_INVALID;
    if (be16(p + h) != 0x86dd) return PC_UNSUPPORTED;
    h += 2;
    if (!ipv6_valid(p + h, n - h)) return PC_INVALID;
    out->sequence = (uint16_t)(p[2] | (uint16_t)p[3] << 8);
    out->ipv6 = p + h; out->ipv6_size = n - h;
    return PC_OK;
}

static int data_walk(const uint8_t *p, size_t n, pc_data_fn callback, void *ctx) {
    if (!p || n < 2) return PC_INVALID;
    if ((p[0] != 0x08 && p[0] != 0x88) || (p[1] & 3)) return PC_OTHER;
    if (n < 24) return PC_INVALID;
    if (memcmp(p + 16, bssid, 6)) return PC_OTHER;
    if ((p[1] & 0xc4) || (p[22] & 15)) return PC_UNSUPPORTED;
    size_t h = p[0] == 0x88 ? 26 : 24;
    if (n < h) return PC_INVALID;
    int aggregate = h == 26 && (p[24] & 0x80);
    struct pc_awdl_data value = {0};
    memcpy(value.source, p + 10, 6); memcpy(value.destination, p + 4, 6);
    if (!aggregate) {
        int result = msdu(p + h, n - h, &value);
        if (result == PC_OK && callback) callback(&value, ctx);
        return result;
    }
    if (n - h > 11454) return PC_UNSUPPORTED;
    value.aggregate = 1;
    unsigned count = 0, matches = 0;
    while (h < n) {
        if (++count > 64) return PC_UNSUPPORTED;
        if (n - h < 14) return PC_INVALID;
        size_t length = be16(p + h + 12);
        if (!length || length > 2304 || length > n - h - 14) return PC_INVALID;
        /* No relayed/foreign addresses are admitted through an aggregate. */
        if (memcmp(p + h, value.destination, 6) || memcmp(p + h + 6, value.source, 6)) return PC_UNSUPPORTED;
        int result = msdu(p + h + 14, length, &value);
        if (result != PC_OK && result != PC_OTHER) return result;
        if (result == PC_OK) {
            matches++;
            if (callback) callback(&value, ctx);
        }
        h += 14 + length;
        if (h == n) break; /* The final subframe has no padding. */
        size_t padding = (4 - ((14 + length) % 4)) % 4;
        if (n - h < padding + 14) return PC_INVALID;
        h += padding; /* Padding byte values are unspecified. */
    }
    if (!count) return PC_INVALID;
    return matches ? PC_OK : PC_OTHER;
}

int pc_awdl_data_visit(const uint8_t *p, size_t n, pc_data_fn callback, void *ctx) {
    int result = data_walk(p, n, NULL, NULL);
    if (result == PC_OK && callback) return data_walk(p, n, callback, ctx);
    return result;
}

struct single_data { struct pc_awdl_data value; unsigned count; };
static void single(const struct pc_awdl_data *data, void *ctx) {
    struct single_data *s = ctx;
    s->value = *data; s->count++;
}
int pc_awdl_data_parse(const uint8_t *p, size_t n, struct pc_awdl_data *out) {
    if (!out) return PC_INVALID;
    struct single_data s = {0};
    int result = pc_awdl_data_visit(p, n, single, &s);
    if (result != PC_OK) return result;
    if (s.count != 1) return PC_UNSUPPORTED;
    *out = s.value;
    return PC_OK;
}

int pc_awdl_data_build(const uint8_t source[6], const uint8_t destination[6], uint16_t sequence,
                       const uint8_t *ipv6, size_t n, uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written = 0;
    if (!unicast(source) || !destination || !out || !ipv6_valid(ipv6, n) || capacity < 42 + n)
        return PC_INVALID;
    memset(out, 0, 42);
    out[0] = 0x88;
    /* Native Mac captures r35/r62 use best-effort TID 0 for UDP/TCP,
     * while Neighbor Advertisements use TID 6. */
    out[24] = ipv6[6] == 17 || ipv6[6] == 6 ? 0 : 6;
    memcpy(out + 4, destination, 6); memcpy(out + 10, source, 6); memcpy(out + 16, bssid, 6);
    le(out + 22, (uint16_t)((sequence & 0xfff) << 4));
    memcpy(out + 26, snap, 8);
    out[34] = 3; out[35] = 4; le(out + 36, sequence);
    be(out + 40, 0x86dd); memcpy(out + 42, ipv6, n);
    *written = 42 + n;
    return PC_OK;
}

/* Diagnostic alternative to QoS data: remove only the two-byte QoS Control
 * field, retaining the same AWDL MSDU and independent sequence header. */
int pc_awdl_data_build_legacy(const uint8_t source[6], const uint8_t destination[6], uint16_t sequence,
                              const uint8_t *ipv6, size_t n, uint8_t *out, size_t capacity, size_t *written) {
    int result = pc_awdl_data_build(source, destination, sequence, ipv6, n, out, capacity, written);
    if (result != PC_OK) return result;
    out[0] = 0x08;
    memmove(out + 24, out + 26, *written - 26);
    *written -= 2;
    return PC_OK;
}

static uint16_t transport_checksum(const uint8_t *ip, size_t n) {
    uint32_t sum = ip[6] + (uint32_t)(n - 40);
    for (size_t i = 8; i < 40; i += 2) sum += be16(ip + i);
    for (size_t i = 40; i + 1 < n; i += 2) sum += be16(ip + i);
    if (n & 1) sum += (uint32_t)ip[n - 1] << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

int pc_echo_build(const uint8_t source[6], const uint8_t destination[6], uint16_t id,
                   uint16_t sequence, const uint8_t nonce[8], uint8_t out[56]) {
    if (!unicast(source) || !unicast(destination) || !nonce || !out) return PC_INVALID;
    memset(out, 0, 56); out[0] = 0x60; out[5] = 16; out[6] = 58; out[7] = 64;
    pc_linklocal(source, out + 8); pc_linklocal(destination, out + 24);
    out[40] = 128; be(out + 44, id); be(out + 46, sequence);
    memcpy(out + 48, nonce, 8); be(out + 42, transport_checksum(out, 56));
    return PC_OK;
}

int pc_echo_reply(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t id, uint16_t sequence, const uint8_t nonce[8]) {
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !nonce) return PC_INVALID;
    if (n != 56 || ip[6] != 58 || ip[40] != 129 || ip[41] != 0) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(peer, address); if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    if (be16(ip + 44) != id || be16(ip + 46) != sequence || memcmp(ip + 48, nonce, 8)) return PC_OTHER;
    return transport_checksum(ip, n) ? PC_INVALID : PC_OK;
}

int pc_echo_respond(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                     uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written = 0;
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) || !out) return PC_INVALID;
    if (ip[6] != 58 || n < 48 || ip[40] != 128 || ip[41] || !ip[7]) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(peer, address); if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    if (transport_checksum(ip, n) || capacity < n) return PC_INVALID;
    /* Preserve payload before replacing the header, including in-place use. */
    memmove(out + 40, ip + 40, n - 40);
    memset(out, 0, 40); out[0] = 0x60; be(out + 4, (uint16_t)(n - 40)); out[6] = 58; out[7] = 64;
    pc_linklocal(own, out + 8); pc_linklocal(peer, out + 24);
    out[40] = 129; out[42] = out[43] = 0;
    be(out + 42, transport_checksum(out, n));
    *written = n;
    return PC_OK;
}

static int neighbor_options(const uint8_t *ip, size_t n, uint8_t kind, const uint8_t mac[6], unsigned *found) {
    *found = 0;
    for (size_t offset = 64; offset < n;) {
        if (n - offset < 2 || !ip[offset + 1]) return PC_INVALID;
        size_t length = (size_t)ip[offset + 1] * 8;
        if (length > n - offset) return PC_INVALID;
        if (ip[offset] == kind) {
            if (length != 8 || ++*found > 1) return PC_INVALID;
            if (memcmp(ip + offset + 2, mac, 6)) return PC_OTHER;
        }
        offset += length;
    }
    return PC_OK;
}

int pc_neighbor_build(const uint8_t own[6], const uint8_t peer[6], uint8_t out[72]) {
    if (!unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) || !out) return PC_INVALID;
    memset(out, 0, 72);
    out[0] = 0x60; out[5] = 32; out[6] = 58; out[7] = 255;
    pc_linklocal(own, out + 8); pc_linklocal(peer, out + 48);
    out[24] = 0xff; out[25] = 2; out[35] = 1; out[36] = 0xff;
    memcpy(out + 37, out + 61, 3);
    out[40] = 135; out[64] = 1; out[65] = 1; memcpy(out + 66, own, 6);
    be(out + 42, transport_checksum(out, 72));
    return PC_OK;
}

int pc_neighbor_reply(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6]) {
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6)) return PC_INVALID;
    if (ip[6] != 58 || n < 64 || ip[40] != 136) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    pc_linklocal(peer, address);
    if (memcmp(ip + 8, address, 16) || memcmp(ip + 48, address, 16)) return PC_OTHER;
    if (ip[7] != 255 || ip[41] || !(ip[44] & 0x40) || transport_checksum(ip, n)) return PC_INVALID;
    unsigned found;
    int result = neighbor_options(ip, n, 2, peer, &found);
    return result != PC_OK ? result : found == 1 ? PC_OK : PC_INVALID;
}

int pc_neighbor_respond(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                        uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written = 0;
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) || !out)
        return PC_INVALID;
    if (ip[6] != 58 || n < 64 || ip[40] != 135) return PC_OTHER;
    uint8_t local[16], remote[16], group[16] = {0xff, 2};
    pc_linklocal(own, local); pc_linklocal(peer, remote);
    group[11] = 1; group[12] = 0xff; memcpy(group + 13, local + 13, 3);
    if (memcmp(ip + 8, remote, 16) || memcmp(ip + 48, local, 16) ||
        (memcmp(ip + 24, local, 16) && memcmp(ip + 24, group, 16))) return PC_OTHER;
    if (ip[7] != 255 || ip[41] || transport_checksum(ip, n)) return PC_INVALID;
    unsigned source_options;
    int result = neighbor_options(ip, n, 1, peer, &source_options);
    if (result != PC_OK) return result;
    if (capacity < 72) return PC_INVALID;
    /* Build separately so input and output may alias without destroying NS. */
    uint8_t reply[72] = {0};
    reply[0] = 0x60; reply[5] = 32; reply[6] = 58; reply[7] = 255;
    memcpy(reply + 8, local, 16); memcpy(reply + 24, remote, 16);
    reply[40] = 136; reply[44] = 0x60; /* solicited, override; never router */
    memcpy(reply + 48, local, 16);
    reply[64] = 2; reply[65] = 1; memcpy(reply + 66, own, 6);
    be(reply + 42, transport_checksum(reply, sizeof(reply)));
    memcpy(out, reply, sizeof(reply)); *written = sizeof(reply);
    return PC_OK;
}

static const uint8_t udp_marker[16] = {'P','i','C','a','s','t',' ','U','D','P',' ','p','r','o','b','e'};

int pc_udp_build(const uint8_t own[6], const uint8_t peer[6], uint16_t port, uint16_t id,
                  uint16_t sequence, const uint8_t token[16], uint8_t out[84]) {
    if (!unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) || port < 1024 || !token || !out) return PC_INVALID;
    memset(out, 0, 84); out[0] = 0x60; out[5] = 44; out[6] = 17; out[7] = 64;
    pc_linklocal(own, out + 8); pc_linklocal(peer, out + 24);
    be(out + 40, (uint16_t)(49152U + (id & 0x3fff))); be(out + 42, port); be(out + 44, 44);
    memcpy(out + 48, token, 16); be(out + 64, id); be(out + 66, sequence); memcpy(out + 68, udp_marker, sizeof(udp_marker));
    uint16_t checksum = transport_checksum(out, 84);
    be(out + 46, checksum ? checksum : 65535);
    return PC_OK;
}

int pc_udp_respond(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                   uint16_t port, const uint8_t token[16], uint8_t out[84]) {
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) ||
        !token || !out || port < 1024) return PC_INVALID;
    if (n != 84 || ip[6] != 17 || !ip[7] || be16(ip + 40) < 1024 || be16(ip + 42) != port) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(peer, address); if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    if (be16(ip + 44) != 44 || !be16(ip + 46) || transport_checksum(ip, n)) return PC_INVALID;
    if (memcmp(ip + 48, token, 16) || be16(ip + 64) != 0x5043 ||
        be16(ip + 66) < 1 || be16(ip + 66) > 3 || memcmp(ip + 68, udp_marker, 16)) return PC_OTHER;
    uint16_t source_port = be16(ip + 40);
    memmove(out, ip, 84);
    memset(out, 0, 40); out[0] = 0x60; out[5] = 44; out[6] = 17; out[7] = 64;
    pc_linklocal(own, out + 8); pc_linklocal(peer, out + 24);
    be(out + 40, port); be(out + 42, source_port); out[46] = out[47] = 0;
    uint16_t checksum = transport_checksum(out, 84);
    be(out + 46, checksum ? checksum : 65535);
    return PC_OK;
}

int pc_udp_reply(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t port, uint16_t id, uint16_t sequence, const uint8_t token[16]) {
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer) || !memcmp(own, peer, 6) || !token || port < 1024) return PC_INVALID;
    if (n != 84 || ip[6] != 17 || be16(ip + 40) != port ||
        be16(ip + 42) != (uint16_t)(49152U + (id & 0x3fff))) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(peer, address); if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    if (be16(ip + 44) != 44 || !be16(ip + 46) || transport_checksum(ip, n)) return PC_INVALID;
    if (memcmp(ip + 48, token, 16) || be16(ip + 64) != id || be16(ip + 66) != sequence ||
        memcmp(ip + 68, udp_marker, sizeof(udp_marker))) return PC_OTHER;
    return PC_OK;
}

static const uint8_t question[34] = {
    9, '_','s','e','r','v','i','c','e','s', 7, '_','d','n','s','-','s','d',
    4, '_','u','d','p', 5, 'l','o','c','a','l', 0, 0,12, 0,1
};

int pc_mdns_build(const uint8_t source[6], const uint8_t destination[6], uint16_t id, uint8_t out[94]) {
    if (!unicast(source) || !unicast(destination) || !out) return PC_INVALID;
    memset(out, 0, 94); out[0] = 0x60; out[5] = 54; out[6] = 17; out[7] = 255;
    pc_linklocal(source, out + 8); pc_linklocal(destination, out + 24);
    be(out + 40, (uint16_t)(49152U + (id & 0x3fff))); be(out + 42, 5353); be(out + 44, 54);
    be(out + 48, id); be(out + 52, 1); memcpy(out + 60, question, sizeof(question));
    uint16_t checksum = transport_checksum(out, 94);
    be(out + 46, checksum ? checksum : 65535);
    return PC_OK;
}

static const uint8_t diag_name[24] = {11,'_','p','i','c','a','s','t','d','i','a','g',4,'_','u','d','p',5,'l','o','c','a','l',0};
static const uint8_t mdns_group[16] = {0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};

int pc_mdns_group_build(const uint8_t source[6], uint8_t out[88]) {
    if (!unicast(source) || !out) return PC_INVALID;
    memset(out, 0, 88); out[0] = 0x60; out[5] = 48; out[6] = 17; out[7] = 255;
    pc_linklocal(source, out + 8); memcpy(out + 24, mdns_group, 16);
    be(out + 40, 5353); be(out + 42, 5353); be(out + 44, 48);
    be(out + 52, 1); memcpy(out + 60, diag_name, sizeof(diag_name));
    be(out + 84, 12); be(out + 86, 1); /* PTR, IN, multicast response requested */
    uint16_t checksum = transport_checksum(out, 88);
    be(out + 46, checksum ? checksum : 65535);
    return PC_OK;
}

static size_t service_record(uint8_t *out, const uint8_t *name, size_t name_size,
                              uint16_t type, uint16_t cls, const uint8_t *data, size_t size) {
    memcpy(out, name, name_size); out += name_size;
    be(out, type); be(out + 2, cls);
    memset(out + 4, 0, 4); out[7] = 15;
    be(out + 8, (uint16_t)size); memcpy(out + 10, data, size);
    return name_size + 10 + size;
}

static int service_build(const uint8_t source[6], const uint8_t token[16], int tcp, uint8_t out[421]) {
    uint8_t service_name[sizeof(diag_name)]; memcpy(service_name, diag_name, sizeof(diag_name));
    if (tcp) memcpy(service_name + 14, "tcp", 3);
    if (!unicast(source) || !token || !out) return PC_INVALID;
    const char digits[] = "0123456789abcdef";
    uint8_t text_token[32];
    for (size_t i = 0; i < 16; i++) {
        text_token[2 * i] = (uint8_t)digits[token[i] >> 4];
        text_token[2 * i + 1] = (uint8_t)digits[token[i] & 15];
    }
    uint8_t instance[68] = {43}, host[14] = {6,'p','i','c','a','s','t',5,'l','o','c','a','l',0}, srv[20] = {0}, txt[43] = {3,'v','=','1',38};
    memcpy(instance + 1, "PiCast-lab-", 11); memcpy(instance + 12, text_token, 32);
    memcpy(instance + 44, service_name, sizeof(service_name));
    /* Match the existing AWDL ARPA hostname; only the instance is fresh. */
    be(srv + 4, 37000); memcpy(srv + 6, host, sizeof(host));
    memcpy(txt + 5, "token=", 6); memcpy(txt + 11, text_token, 32);
    memset(out, 0, 421); out[0] = 0x60; be(out + 4, 381); out[6] = 17; out[7] = 255;
    pc_linklocal(source, out + 8); memcpy(out + 24, mdns_group, 16);
    be(out + 40, 5353); be(out + 42, 5353); be(out + 44, 381);
    be(out + 50, 0x8400); be(out + 54, 1); be(out + 58, 3);
    size_t n = 60;
    n += service_record(out + n, service_name, sizeof(service_name), 12, 1, instance, sizeof(instance));
    n += service_record(out + n, instance, sizeof(instance), 33, 0x8001, srv, sizeof(srv));
    n += service_record(out + n, instance, sizeof(instance), 16, 0x8001, txt, sizeof(txt));
    n += service_record(out + n, host, sizeof(host), 28, 0x8001, out + 8, 16);
    if (n != 421) return PC_INVALID;
    uint16_t checksum = transport_checksum(out, n);
    be(out + 46, checksum ? checksum : 65535);
    return PC_OK;
}

int pc_service_build(const uint8_t source[6], const uint8_t token[16], uint8_t out[421]) {
    return service_build(source, token, 0, out);
}
int pc_tcp_service_build(const uint8_t source[6], const uint8_t token[16], uint8_t out[421]) {
    return service_build(source, token, 1, out);
}

static int airplay_service_build(const uint8_t source[6], const uint8_t token[16], const uint8_t pk[32],
                             uint8_t *out, size_t capacity, size_t *written, int p2p_only) {
    if (!written) return PC_INVALID;
    *written=0;
    if (!unicast(source) || !token || !pk || !out) return PC_INVALID;
    static const uint8_t normal_service[]={8,'_','a','i','r','p','l','a','y',4,'_','t','c','p',5,'l','o','c','a','l',0};
    static const uint8_t p2p_service[]={12,'_','a','i','r','p','l','a','y','-','p','2','p',4,'_','t','c','p',5,'l','o','c','a','l',0};
    const uint8_t *service=p2p_only ? p2p_service : normal_service;
    size_t service_n=p2p_only ? sizeof(p2p_service) : sizeof(normal_service);
    static const uint8_t host[]={6,'p','i','c','a','s','t',5,'l','o','c','a','l',0};
    static const uint8_t raop_service[]={5,'_','r','a','o','p',4,'_','t','c','p',5,'l','o','c','a','l',0};
    uint8_t raop_instance[64+sizeof(raop_service)], raop_txt[320]; size_t raop_n=0, raop_instance_n=0;
    static const char digits[]="0123456789abcdef";
    uint8_t instance[64+sizeof(p2p_service)], srv[6+sizeof(host)]={0}, txt[320]; size_t text_n=0;
    size_t instance_n=0;
    char nonce[33], public_hex[65], device[27];
    for (size_t i=0;i<16;i++) { nonce[i*2]=digits[token[i]>>4]; nonce[i*2+1]=digits[token[i]&15]; }
    nonce[32]=0;
    for (size_t i=0;i<32;i++) { public_hex[i*2]=digits[pk[i]>>4]; public_hex[i*2+1]=digits[pk[i]&15]; }
    public_hex[64]=0;
    snprintf(device,sizeof(device),"deviceid=%02X:%02X:%02X:%02X:%02X:%02X",source[0],source[1],source[2],source[3],source[4],source[5]);
    char key[68], token_text[39], pairing_id[37], pairing_text[40], system_id[37], system_text[41];
    pc_airplay_pairing_id(pk,pairing_id);
    pc_airplay_pairing_id(pk+16,system_id);
    snprintf(pairing_text,sizeof(pairing_text),"pi=%s",pairing_id);
    snprintf(system_text,sizeof(system_text),"psi=%s",system_id);
    snprintf(key,sizeof(key),"pk=%s",public_hex); snprintf(token_text,sizeof(token_text),"token=%s",nonce);
    char features[32]; snprintf(features,sizeof(features),"features=0x%llx",(unsigned long long)pc_airplay_features());
    const char *fields[]={device,features,"model=" PC_AIRPLAY_MODEL,"srcvers=" PC_AIRPLAY_SOURCE_VERSION,"flags=0x0",key,"pw=false","protovers=1.0",token_text,pairing_text,system_text,
        "vv=2",
    };
    for (size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
        size_t n=strlen(fields[i]);
        if (n>255 || 1+n>sizeof(txt)-text_n) return PC_INVALID;
        txt[text_n++]=(uint8_t)n; memcpy(txt+text_n,fields[i],n); text_n+=n;
    }
    /* The name in the AirPlay menu (picast.txt, passed on as PICAST_NAME). */
    const char *shown_name=pc_receiver_name();
    char instance_label[64];
    int instance_label_n=p2p_only ? snprintf(instance_label,sizeof(instance_label),"%02X%02X%02X%02X%02X%02X@%s",source[0],source[1],source[2],source[3],source[4],source[5],shown_name) : snprintf(instance_label,sizeof(instance_label),"%s",shown_name);
    if (instance_label_n<1 || instance_label_n>=(int)sizeof(instance_label)) return PC_INVALID;
    instance[0]=(uint8_t)instance_label_n; memcpy(instance+1,instance_label,(size_t)instance_label_n);
    instance_n=1+(size_t)instance_label_n+service_n;
    memcpy(instance+1+instance_label_n,service,service_n); be(srv+4,37000); memcpy(srv+6,host,sizeof(host));
    size_t needed=60+service_n+10+instance_n+2*(instance_n+10)+sizeof(srv)+text_n+sizeof(host)+10+16;
    if (!p2p_only) {
    char raop_label[64];
    int label_n=snprintf(raop_label,sizeof(raop_label),"%02X%02X%02X%02X%02X%02X@%s",source[0],source[1],source[2],source[3],source[4],source[5],shown_name);
    if (label_n<1 || label_n>=(int)sizeof(raop_label)) return PC_INVALID;
    raop_instance[0]=(uint8_t)label_n; memcpy(raop_instance+1,raop_label,(size_t)label_n);
    memcpy(raop_instance+1+label_n,raop_service,sizeof(raop_service));
    raop_instance_n=1+(size_t)label_n+sizeof(raop_service);
    char audio_features[32];
    snprintf(audio_features,sizeof(audio_features),"ft=0x%llx",(unsigned long long)pc_airplay_features());
    const char *audio[]={"txtvers=1","ch=2",
        "cn=0,3",
        "et=0,3",
        "pw=false","sr=44100","ss=16","tp=UDP","vn=65537","vs=" PC_AIRPLAY_SOURCE_VERSION,"am=" PC_AIRPLAY_MODEL,"sf=0x0",audio_features,"vv=2",key,pairing_text,system_text};
    for (size_t i=0;i<sizeof(audio)/sizeof(audio[0]);i++) {
        size_t count=strlen(audio[i]);
        if (count>255 || count+1>sizeof(raop_txt)-raop_n) return PC_INVALID;
        raop_txt[raop_n++]=(uint8_t)count; memcpy(raop_txt+raop_n,audio[i],count); raop_n+=count;
    }
    needed+=sizeof(raop_service)+10+raop_instance_n+2*(raop_instance_n+10)+sizeof(srv)+raop_n;
    }
    if (needed>1280 || needed>capacity) return PC_INVALID;
    uint8_t packet[1280]={0}; packet[0]=0x60; packet[6]=17; packet[7]=255;
    pc_linklocal(source,packet+8); memcpy(packet+24,mdns_group,16);
    be(packet+40,5353); be(packet+42,5353); be(packet+50,0x8400); be(packet+54,1); be(packet+58,3);
    if (!p2p_only) { be(packet+54,2); be(packet+58,5); }
    size_t n=60;
    n+=service_record(packet+n,service,service_n,12,1,instance,instance_n);
    if (!p2p_only) n+=service_record(packet+n,raop_service,sizeof(raop_service),12,1,raop_instance,raop_instance_n);
    n+=service_record(packet+n,instance,instance_n,33,0x8001,srv,sizeof(srv));
    n+=service_record(packet+n,instance,instance_n,16,0x8001,txt,text_n);
    n+=service_record(packet+n,host,sizeof(host),28,0x8001,packet+8,16);
    if (!p2p_only) {
        n+=service_record(packet+n,raop_instance,raop_instance_n,33,0x8001,srv,sizeof(srv));
        n+=service_record(packet+n,raop_instance,raop_instance_n,16,0x8001,raop_txt,raop_n);
    }
    if (n>capacity) return PC_INVALID;
    be(packet+4,(uint16_t)(n-40)); be(packet+44,(uint16_t)(n-40));
    uint16_t checksum=transport_checksum(packet,n); be(packet+46,checksum ? checksum : 65535);
    memcpy(out,packet,n); *written=n; return PC_OK;
}

int pc_airplay_service_build(const uint8_t source[6], const uint8_t token[16], const uint8_t pk[32],
                             uint8_t *out, size_t capacity, size_t *written) {
    return airplay_service_build(source,token,pk,out,capacity,written,0);
}
int pc_airplay_p2p_service_build(const uint8_t source[6], const uint8_t token[16], const uint8_t pk[32],
                             uint8_t *out, size_t capacity, size_t *written) {
    return airplay_service_build(source,token,pk,out,capacity,written,1);
}

static int dns_name(const uint8_t *p, size_t n, size_t *position, uint8_t *name, size_t *name_size) {
    size_t cursor = *position, consumed = 0, expanded = 0;
    for (unsigned steps = 0; steps < 256; steps++) {
        if (cursor >= n) return PC_INVALID;
        uint8_t label = p[cursor];
        if ((label & 0xc0) == 0xc0) {
            if (n - cursor < 2) return PC_INVALID;
            size_t target = (size_t)(label & 0x3f) * 256 + p[cursor + 1];
            if (target >= cursor) return PC_INVALID; /* backward pointers, no loops */
            if (!consumed) consumed = cursor + 2 - *position;
            cursor = target; continue;
        }
        if (label & 0xc0) return PC_INVALID;
        cursor++;
        if (expanded + (size_t)label + 1 > 255 || (size_t)label > n - cursor) return PC_INVALID;
        if (name) {
            name[expanded] = label;
            for (size_t i = 0; i < label; i++) {
                uint8_t c = p[cursor + i];
                name[expanded + 1 + i] = c >= 'A' && c <= 'Z' ? (uint8_t)(c + 'a' - 'A') : c;
            }
        }
        expanded += (size_t)label + 1;
        if (!label) {
            *position += consumed ? consumed : cursor - *position;
            if (name_size) *name_size = expanded;
            return PC_OK;
        }
        cursor += label;
    }
    return PC_INVALID;
}

int pc_mdns_reply(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t id, uint16_t *answers) {
    if (!answers) return PC_INVALID;
    *answers = 0;
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer)) return PC_INVALID;
    if (n < 94 || ip[6] != 17 || be16(ip + 40) != 5353 ||
        be16(ip + 42) != (uint16_t)(49152U + (id & 0x3fff))) return PC_OTHER;
    uint8_t address[16];
    pc_linklocal(peer, address); if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address); if (memcmp(ip + 24, address, 16)) return PC_OTHER;
    if ((size_t)be16(ip + 44) != n - 40 || !be16(ip + 46) || transport_checksum(ip, n)) return PC_INVALID;
    const uint8_t *dns = ip + 48; size_t size = n - 48;
    if (be16(dns) != id || !(dns[2] & 0x80) || (dns[2] & 0x78) || (dns[3] & 15)) return PC_OTHER;
    if (be16(dns + 4) != 1 || memcmp(dns + 12, question, sizeof(question))) return PC_OTHER;
    uint32_t records = (uint32_t)be16(dns + 6) + be16(dns + 8) + be16(dns + 10);
    if (records > 256) return PC_UNSUPPORTED;
    size_t pos = 12 + sizeof(question);
    for (uint32_t i = 0; i < records; i++) {
        if (dns_name(dns, size, &pos, NULL, NULL) != PC_OK || size - pos < 10) return PC_INVALID;
        size_t length = be16(dns + pos + 8); pos += 10;
        if (length > size - pos) return PC_INVALID;
        pos += length;
    }
    if (pos != size) return PC_INVALID;
    *answers = be16(dns + 6);
    return PC_OK;
}

int pc_mdns_group_reply(const uint8_t *ip, size_t n, const uint8_t own[6], const uint8_t peer[6], uint16_t *answers) {
    if (!answers) return PC_INVALID;
    *answers = 0;
    if (!ipv6_valid(ip, n) || !unicast(own) || !unicast(peer)) return PC_INVALID;
    if (n < 60 || ip[6] != 17 || be16(ip + 40) != 5353 || be16(ip + 42) != 5353) return PC_OTHER;
    uint8_t address[16]; pc_linklocal(peer, address);
    if (memcmp(ip + 8, address, 16)) return PC_OTHER;
    pc_linklocal(own, address);
    if (memcmp(ip + 24, mdns_group, 16) && memcmp(ip + 24, address, 16)) return PC_OTHER;
    if (ip[7] != 255 || (size_t)be16(ip + 44) != n - 40 || !be16(ip + 46) || transport_checksum(ip, n)) return PC_INVALID;
    const uint8_t *dns = ip + 48; size_t size = n - 48, pos = 12;
    if (be16(dns) || be16(dns + 2) != 0x8400) return PC_OTHER;
    uint32_t records = (uint32_t)be16(dns + 6) + be16(dns + 8) + be16(dns + 10);
    if (be16(dns + 4) > 64 || records > 256) return PC_UNSUPPORTED;
    for (unsigned i = 0; i < be16(dns + 4); i++) {
        if (dns_name(dns, size, &pos, NULL, NULL) != PC_OK || size - pos < 4) return PC_INVALID;
        pos += 4;
    }
    uint16_t matched = 0;
    for (uint32_t i = 0; i < records; i++) {
        uint8_t name[255]; size_t name_size;
        if (dns_name(dns, size, &pos, name, &name_size) != PC_OK || size - pos < 10) return PC_INVALID;
        uint16_t type = be16(dns + pos), cls = (uint16_t)(be16(dns + pos + 2) & 0x7fff);
        size_t length = be16(dns + pos + 8); pos += 10;
        if (length > size - pos) return PC_INVALID;
        if (type == 12 && cls == 1 && name_size == sizeof(diag_name) && !memcmp(name, diag_name, sizeof(diag_name))) {
            size_t end = pos;
            if (dns_name(dns, size, &end, NULL, NULL) != PC_OK || end != pos + length) return PC_INVALID;
            matched++;
        }
        pos += length;
    }
    if (pos != size) return PC_INVALID;
    *answers = matched;
    return matched ? PC_OK : PC_OTHER;
}

/* picast: the receiver program. The device runner (tools/picast_product.py)
 * calls it; the commands below are its building blocks, not a user interface. */
#include "picast.h"
#include "picast_config.h"
#include "picast_ui.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef PICAST_VERSION
#define PICAST_VERSION "dev"
#endif

static double timestamp(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t)) return 0;
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void print_item(uint8_t type, const uint8_t *p, size_t n, void *ctx) {
    printf("{\"type\":%u,\"length\":%zu,\"hex\":\"", type, n);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\"");
    if (ctx && type == 4) {
        struct pc_awdl_sync s;
        if (pc_awdl_sync_parse(p, n, &s) == PC_OK)
            printf(",\"sync\":{\"tx_channel\":%u,\"master_channel\":%u,\"tx_counter\":%u,"
                   "\"aw_period_tu\":%u,\"action_period_tu\":%u,\"aw_counter\":%u,\"presence\":%u}",
                   s.tx_channel, s.master_channel, s.tx_counter, s.aw_period_tu,
                   s.action_period_tu, s.aw_counter, s.presence);
    }
    if (ctx && type == 18) {
        struct pc_awdl_channels c;
        if (pc_awdl_channels_parse(p, n, &c) == PC_OK) {
            printf(",\"channel_sequence\":{\"encoding\":3,\"duplicate\":%u,\"step\":%u,\"fill\":%u,\"channels\":[",
                   c.duplicate, c.step, c.fill);
            for (uint16_t i = 0; i < c.count; i++)
                printf("%s{\"number\":%u,\"operating_class\":%u}", i ? "," : "", c.number[i], c.operating_class[i]);
            printf("]}");
        }
    }
    if (ctx && type == 21 && n == 2)
        printf(",\"version_tag\":{\"version_raw\":%u,\"device_class\":%u}", p[0], p[1]);
    printf("}\n");
}

int pc_print_awdl(const uint8_t *p, size_t n) {
    struct pc_awdl a;
    int rc = pc_awdl_parse(p, n, &a, NULL, NULL);
    if (rc != PC_OK) return rc;
    printf("{\"event\":\"awdl_action\",\"observed_epoch_seconds\":%.6f,\"version\":%u,\"subtype\":%u,"
           "\"phy_time\":%u,\"target_time\":%u,\"tags\":%zu,"
           "\"source\":\"%02x:%02x:%02x:%02x:%02x:%02x\"}\n",
           timestamp(), a.version, a.subtype, a.phy_time, a.target_time, a.tags,
           a.source[0], a.source[1], a.source[2], a.source[3], a.source[4], a.source[5]);
    (void)pc_awdl_parse(p, n, &a, print_item, &a);
    return PC_OK;
}

static void print_data(const struct pc_awdl_data *d, void *ctx) {
    (void)ctx;
    char source[INET6_ADDRSTRLEN], destination[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, d->ipv6 + 8, source, sizeof(source)) ||
        !inet_ntop(AF_INET6, d->ipv6 + 24, destination, sizeof(destination))) return;
    printf("{\"event\":\"awdl_data\",\"sequence\":%u,\"ipv6_size\":%zu,\"source_ip\":\"%s\","
           "\"destination_ip\":\"%s\",\"next_header\":%u,\"aggregate\":%s,\"long_header\":%s,"
           "\"source\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
           "\"destination\":\"%02x:%02x:%02x:%02x:%02x:%02x\"}\n",
           d->sequence, d->ipv6_size, source, destination, d->ipv6[6],
           d->aggregate ? "true" : "false", d->long_header ? "true" : "false",
           d->source[0], d->source[1], d->source[2], d->source[3], d->source[4], d->source[5],
           d->destination[0], d->destination[1], d->destination[2],
           d->destination[3], d->destination[4], d->destination[5]);
}

int pc_print_awdl_data(const uint8_t *p, size_t n) {
    return pc_awdl_data_visit(p, n, print_data, NULL);
}

static int hex(const char *s, uint8_t *p, size_t capacity, size_t *size) {
    size_t n = 0; int high = -1;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isspace(c) || c == ':') continue;
        int digit = c >= '0' && c <= '9' ? c - '0' :
                    c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                    c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (digit < 0) return -1;
        if (high < 0) high = digit;
        else {
            if (n == capacity) return -1;
            p[n++] = (uint8_t)(high * 16 + digit); high = -1;
        }
    }
    if (high >= 0) return -1;
    *size = n; return 0;
}

struct analysis { size_t total, awdl, data, invalid, unsupported; };
static int analyze_packet(const struct pc_pcap_packet *packet, void *ctx) {
    struct analysis *s = ctx;
    s->total++;
    if (packet->size != packet->original_size) { s->invalid++; return PC_OK; }
    const uint8_t *frame = packet->data; size_t length = packet->size;
    int rc = packet->linktype == 127 ? pc_radiotap(packet->data, packet->size, &frame, &length) : PC_OK;
    if (rc == PC_OK) {
        rc = pc_print_awdl(frame, length);
        if (rc == PC_OK) s->awdl++;
        else if (rc == PC_OTHER) {
            rc = pc_print_awdl_data(frame, length);
            if (rc == PC_OK) s->data++;
        }
    }
    if (rc == PC_INVALID) s->invalid++;
    else if (rc == PC_UNSUPPORTED) s->unsupported++;
    return PC_OK;
}
/* The runner reads this to find senders nearby; the summary line marks a capture
 * that could be read at all. */
static int analyze(const char *path) {
    struct analysis s = {0};
    if (pc_pcap_walk(path, analyze_packet, &s) != PC_OK) {
        fputs("Unreadable capture (classic PCAP, linktype 105 or 127 expected)\n", stderr);
        return 1;
    }
    printf("{\"event\":\"summary\",\"packets\":%zu,\"awdl_actions\":%zu,"
           "\"awdl_data\":%zu,\"invalid_or_truncated\":%zu,\"unsupported\":%zu}\n",
           s.total, s.awdl, s.data, s.invalid, s.unsupported);
    return s.invalid ? 1 : 0;
}

static int number(const char *s, unsigned max, unsigned *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    errno = 0; char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || v > max) return -1;
    *out = (unsigned)v; return 0;
}

/* One mirroring session with the sender PEER, until it leaves (at most 12 hours). */
static int serve(const char *interface, const char *peer_text, const char *token_text) {
    uint8_t peer[6], token[16]; size_t n;
    if (hex(peer_text, peer, sizeof(peer), &n) || n != 6 || (peer[0] & 1) ||
        !memcmp(peer, (const uint8_t[6]){0}, 6) || hex(token_text, token, sizeof(token), &n) || n != 16) return 2;
    unsigned options = PC_PROBE_FOLLOW | PC_PROBE_OFDM | PC_PROBE_SERVICE | PC_PROBE_TCP_SERVICE |
                       PC_PROBE_RTSP_SERVICE | PC_PROBE_NATIVE_CONTROL | PC_PROBE_MEDIA_10M | PC_PROBE_MEDIA_HOLD;
    return pc_udp_probe(interface, peer, PC_PROBE_HOLD_SECONDS, "/dev/null", options, 37000, token);
}

int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "version") || !strcmp(argv[1], "--version"))) {
        puts("PiCast " PICAST_VERSION);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "config")) return pc_config_command(argc, argv);
    if (argc >= 3 && (!strcmp(argv[1], "ui") || !strcmp(argv[1], "ui-png"))) return pc_ui_command(argc, argv);
    if (argc == 5 && !strcmp(argv[1], "serve")) return serve(argv[2], argv[3], argv[4]);
    if (argc == 3 && !strcmp(argv[1], "analyze")) return analyze(argv[2]);
    if (argc == 5 && !strcmp(argv[1], "capture")) {
        unsigned seconds;
        if (number(argv[3], 3600, &seconds) || !seconds) goto usage;
        return pc_capture_to_file(argv[2], seconds, argv[4]);
    }
    if (argc == 3 && !strcmp(argv[1], "radio-counters")) return pc_firmware_counters(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "radio-check")) return pc_firmware_power(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "radio-wake")) return pc_firmware_monitor_awake(argv[2]);
usage:
    fputs("PiCast " PICAST_VERSION ": AirPlay screen mirroring receiver for the Raspberry Pi Zero 2 W.\n"
          "These commands are used by the PiCast service; run it with: systemctl start picast\n"
          "  picast version\n"
          "  picast config [show | maintenance]       settings from " PC_CONFIG_PATH "\n"
          "  picast ui SCREEN [TEXT] | off | battery  draw a receiver screen\n"
          "  picast ui-png SCREEN TEXT OUT.png [WxH]  the same screen as a picture\n"
          "  picast capture MONITOR SECONDS OUT.pcap  record what the radio hears\n"
          "  picast analyze CAPTURE.pcap              senders in a recording, as JSON lines\n"
          "  picast serve MONITOR PEER_MAC TOKEN_HEX  one mirroring session\n"
          "  picast radio-wake|radio-check|radio-counters INTERFACE\n", stderr);
    return 2;
}

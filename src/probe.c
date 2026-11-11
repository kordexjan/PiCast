#include "picast.h"
#include "picast_tcp.h"
#include "picast_trace.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop(int signal) { (void)signal; stopped = 1; }
static double mono(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return t.tv_sec + t.tv_nsec / 1e9;
}
static int record(struct pc_trace *f, const uint8_t *p, size_t n) {
    struct timespec t; uint8_t h[16];
    if (clock_gettime(CLOCK_REALTIME, &t) || t.tv_sec < 0 || (uint64_t)t.tv_sec > UINT32_MAX ||
        pc_pcap_record(h, (uint32_t)t.tv_sec, (uint32_t)(t.tv_nsec / 1000), n) != PC_OK) return -1;
    return pc_trace_write(f,(uint32_t)t.tv_sec,(uint32_t)(t.tv_nsec/1000),p,n)==PC_OK ? 0 : -1;
}

static int transmit(int fd, const struct sockaddr_ll *address, struct pc_trace *pcap, const uint8_t *packet,
                    size_t n, size_t *accepted) {
    if (!pcap->soft_limit && !pc_trace_room(pcap,n)) return -1;
    if (sendto(fd, packet, n, MSG_DONTWAIT, (const struct sockaddr *)address, sizeof(*address)) != (ssize_t)n) {
        perror("probe transmit"); return -1;
    }
    (*accepted)++;
    return record(pcap, packet, n);
}

struct probe_request { const uint8_t *own, *peer, *nonce, *token, *public_key; uint16_t id, udp_port; uint16_t *wire_sequence; unsigned rate; size_t tcp_packet_limit; int mdns, mdns_group, service, tcp_service, legacy, neighbor, group_replies; };
static int request_send(const struct probe_request *r, int fd, const struct sockaddr_ll *address,
                        struct pc_trace *pcap, size_t *attempts, struct pc_awdl_peer *gate) {
    uint8_t ip[1280], outgoing[1344] = {0, 0, 9, 0, 4, 0, 0, 0, 2}; size_t frame_size;
    size_t ip_size = r->service ? 421 : r->mdns_group ? 88 : r->neighbor ? 72 : r->udp_port ? 84 : r->mdns ? 94 : 56;
    outgoing[8] = (uint8_t)r->rate;
    uint16_t seq = (uint16_t)(*attempts + 1);
    uint8_t destination[6]; memcpy(destination, r->peer, 6);
    if (r->neighbor) {
        destination[0] = destination[1] = 0x33; destination[2] = 0xff;
    }
    if (r->mdns_group || r->service) memcpy(destination, (const uint8_t[]){0x33,0x33,0,0,0,0xfb}, 6);
    int built;
    if (r->service && r->tcp_service) {
        if (*attempts & 1U) built=pc_airplay_p2p_service_build(r->own,r->token,r->public_key,ip,sizeof(ip),&ip_size);
        else
        built=pc_airplay_service_build(r->own,r->token,r->public_key,ip,sizeof(ip),&ip_size);
    }
    else
    built=(r->service ? (r->tcp_service ? pc_tcp_service_build : pc_service_build)(r->own, r->token, ip) : r->mdns_group ? pc_mdns_group_build(r->own, ip) : r->neighbor ? pc_neighbor_build(r->own, r->peer, ip) :
         r->udp_port ? pc_udp_build(r->own, r->peer, r->udp_port, r->id, seq, r->token, ip) :
         r->mdns ? pc_mdns_build(r->own, r->peer, r->id, ip) : pc_echo_build(r->own, r->peer, r->id, seq, r->nonce, ip));
    if (built != PC_OK ||
        (r->legacy ? pc_awdl_data_build_legacy : pc_awdl_data_build)(r->own, destination, (uint16_t)(*r->wire_sequence + 1), ip, ip_size,
                            outgoing + 9, sizeof(outgoing) - 9, &frame_size) != PC_OK) return -1;
    if (gate) {
        struct pc_awdl_plan plan;
        int result = pc_awdl_peer_poll(gate, (uint64_t)(mono() * 1e6), &plan);
        if (result == PC_OTHER || (result == PC_OK && !(plan.available & PC_PEER_DATA))) return 1;
        if (result != PC_OK) return -1;
    }
    int sent = transmit(fd, address, pcap, outgoing, frame_size + 9, attempts);
    if (!sent) (*r->wire_sequence)++;
    return sent;
}

enum { ECHO_QUEUE_LENGTH=32, TCP_PACKET_LIMIT=32768 };
struct echo_pending { uint8_t ip[1500]; size_t size; uint64_t expires_us; int neighbor; };
struct echo_queue {
    struct echo_pending packets[ECHO_QUEUE_LENGTH];
    size_t head, count, received, sent, dropped;
    size_t neighbor_received, neighbor_sent, neighbor_dropped, tcp_sent, tcp_dropped;
    size_t udp_received, udp_sent, udp_dropped;
    unsigned udp_queued_sequences;
};
static void echo_pop(struct echo_queue *q) {
    const struct echo_pending *p = &q->packets[q->head];
    if (p->neighbor == 2) q->udp_queued_sequences &= ~(1U << p->ip[67]);
    q->head = (q->head + 1) % ECHO_QUEUE_LENGTH; q->count--;
}
static int echo_send(struct echo_queue *q, const struct probe_request *r, uint64_t now,
                      int fd, const struct sockaddr_ll *address, struct pc_trace *pcap) {
    while (q->count && (q->packets[q->head].expires_us < now || q->sent >= (r->tcp_service ? r->tcp_packet_limit : 10U))) {
        if (q->packets[q->head].neighbor == 3) q->tcp_dropped++;
        else if (q->packets[q->head].neighbor == 2) q->udp_dropped++;
        else if (q->packets[q->head].neighbor) q->neighbor_dropped++;
        else q->dropped++;
        echo_pop(q);
    }
    if (!q->count) return 0;
    const struct echo_pending *p = &q->packets[q->head];
    /* Diagnostic only: changing the link destination distinguishes a unicast
     * path failure from the IPv6/UDP response codec. Never the default. */
    const uint8_t group[6] = {255, 255, 255, 255, 255, 255};
    int group_reply = p->neighbor == 2 && r->group_replies;
    uint8_t frame[1600] = {0, 0, 9, 0, 4, 0, 0, 0, 2}; size_t n;
    frame[8] = (uint8_t)r->rate;
    if ((r->legacy ? pc_awdl_data_build_legacy : pc_awdl_data_build)(r->own, group_reply ? group : r->peer,
            (uint16_t)(*r->wire_sequence + 1), p->ip, p->size, frame + 9, sizeof(frame) - 9, &n) != PC_OK ||
        transmit(fd, address, pcap, frame, n + 9, &q->sent)) return -1;
    (*r->wire_sequence)++;
    if (p->neighbor == 3) q->tcp_sent++;
    else if (p->neighbor == 2) q->udp_sent++;
    else if (p->neighbor) q->neighbor_sent++;
    echo_pop(q);
    printf("{\"event\":\"%s\",\"bytes\":%zu,\"milestone_2\":false}\n",
           p->neighbor == 3 ? "kernel_tcp_packet_submitted" : p->neighbor == 2 ? "owned_udp_reply_transmitted" : p->neighbor ? "owned_neighbor_reply_transmitted" : "owned_echo_reply_transmitted", p->size);
    if (group_reply) puts("{\"event\":\"diagnostic_group_destination\",\"native_unicast_verified\":false}");
    return 0;
}

struct reply_context {
    const uint8_t *own, *peer, *nonce, *token;
    uint16_t id, udp_port;
    size_t attempts, observations;
    int mdns, mdns_group, neighbor;
    struct echo_queue *echo;
    uint64_t observed_us;
    struct pc_tcp_diag *tcp;
    uint8_t *knocking;   /* set when another device opens a control connection */
};
static int control_syn(const struct pc_awdl_data *data, const uint8_t own[6]) {
    const uint8_t *ip = data->ipv6;
    if (!ip || data->ipv6_size < 60 || (ip[0] >> 4) != 6 || ip[6] != 6 || memcmp(data->destination, own, 6)) return 0;
    return ((unsigned)ip[42] << 8 | ip[43]) == 37000 && (ip[53] & 0x12) == 0x02;
}
static void check_reply(const struct pc_awdl_data *data, void *ctx) {
    struct reply_context *r = ctx;
    if (memcmp(data->source, r->peer, 6)) {
        if (r->knocking && control_syn(data, r->own)) memcpy(r->knocking, data->source, 6);
        return;
    }
    uint8_t multicast[6] = {0x33, 0x33, 0xff, r->own[3], r->own[4], r->own[5]};
    int unicast = !memcmp(data->destination, r->own, 6);
    if (r->mdns_group && (unicast || !memcmp(data->destination, (const uint8_t[]){0x33,0x33,0,0,0,0xfb}, 6))) {
        uint16_t answers;
        if (r->attempts && pc_mdns_group_reply(data->ipv6, data->ipv6_size, r->own, r->peer, &answers) == PC_OK) {
            r->observations++;
            printf("{\"event\":\"diagnostic_mdns_ptr_observed\",\"matching_ptr_records\":%u,\"query_causation_proven\":false,\"milestone_2\":false}\n", answers);
        }
        if (!unicast) return;
    }
    if (!unicast && memcmp(data->destination, multicast, 6)) return;
    if (r->tcp && unicast && (data->ipv6[6] == 6
        || data->ipv6[6] == 17
    )) {
        (void)pc_tcp_diag_ingress(r->tcp, data->ipv6, data->ipv6_size);
        return;
    }
    if (r->echo) {
        uint8_t response[1500]; size_t size;
        int neighbor = pc_neighbor_respond(data->ipv6, data->ipv6_size, r->own, r->peer, response, sizeof(response), &size) == PC_OK;
        int udp = !r->tcp && unicast && r->udp_port == 37000 &&
            pc_udp_respond(data->ipv6, data->ipv6_size, r->own, r->peer, 37000, r->token, response) == PC_OK;
        if (udp) {
            unsigned bit = 1U << data->ipv6[67]; /* codec admits only 1..3 */
            /* Coalesce copies only while a reply is pending. A later retry
             * must be answerable if the previous radio delivery was lost.
             * The same exact token/peer checks and ten-reply cap still apply. */
            if (r->echo->udp_queued_sequences & bit) return;
        }
        if (udp) { neighbor = 2; size = 84; }
        if (neighbor || (unicast && pc_echo_respond(data->ipv6, data->ipv6_size, r->own, r->peer, response, sizeof(response), &size) == PC_OK)) {
            struct echo_queue *q = r->echo;
            if (udp) { q->udp_received++; puts("{\"event\":\"owned_udp_request_received\",\"token_and_checksum_verified\":true}"); }
            else if (neighbor) q->neighbor_received++; else q->received++;
            if (q->count == ECHO_QUEUE_LENGTH || q->sent >= 10) {
                if (udp) q->udp_dropped++;
                else if (neighbor) q->neighbor_dropped++; else q->dropped++;
            }
            else {
                struct echo_pending *p = &q->packets[(q->head + q->count) % ECHO_QUEUE_LENGTH];
                memcpy(p->ip, response, size); p->size = size; p->expires_us = r->observed_us + 2000000;
                p->neighbor = neighbor;
                if (udp) q->udp_queued_sequences |= 1U << data->ipv6[67];
                q->count++;
            }
            return;
        }
    }
    if (!unicast) return;
    if (r->neighbor) {
        if (r->attempts && pc_neighbor_reply(data->ipv6, data->ipv6_size, r->own, r->peer) == PC_OK) {
            r->observations++;
            puts("{\"event\":\"direct_ip_neighbor_reply\",\"addresses_option_and_checksum_verified\":true,\"milestone_2\":false}");
        }
    } else if (r->udp_port) {
        if (data->ipv6_size != 84) return;
        uint16_t seq = (uint16_t)((uint16_t)data->ipv6[66] << 8 | data->ipv6[67]);
        if (seq && seq <= r->attempts && pc_udp_reply(data->ipv6, data->ipv6_size, r->own, r->peer,
                r->udp_port, r->id, seq, r->token) == PC_OK) {
            r->observations++;
            printf("{\"event\":\"direct_ip_udp_reply\",\"sequence\":%u,\"token_and_checksum_verified\":true,\"milestone_2\":false}\n", seq);
        }
    } else if (r->mdns) {
        uint16_t answers;
        if (pc_mdns_reply(data->ipv6, data->ipv6_size, r->own, r->peer, r->id, &answers) == PC_OK) {
            r->observations++;
            printf("{\"event\":\"direct_ip_dns_reply\",\"answers\":%u,\"addresses_id_checksum_verified\":true,\"milestone_2\":false}\n", answers);
        }
    } else if (data->ipv6_size == 56) {
        uint16_t seq = (uint16_t)((uint16_t)data->ipv6[46] << 8 | data->ipv6[47]);
        if (seq && seq <= r->attempts && pc_echo_reply(data->ipv6, data->ipv6_size,
                r->own, r->peer, r->id, seq, r->nonce) == PC_OK) {
            r->observations++;
            printf("{\"event\":\"direct_ip_echo_reply\",\"sequence\":%u,\"nonce_and_checksum_verified\":true,\"milestone_2\":false}\n", seq);
        }
    }
}

#define PEER_IDLE_SECONDS 20U
/* Long enough for the closing packets to reach the sender, with one retransmission. */
#define FAREWELL_SECONDS 1.5
/* The sender asked for a PIN or a session and then went silent (r186). */
#define CONTROL_STALL_SECONDS 60.0
/* Timing answers continue on a still screen, unlike video; they stop when frames no
 * longer reach the sender (r187). A working session answered every second. */
#define TIMING_STALL_SECONDS 20.0
#define HEALTH_SECONDS 5.0
#define PEER_UNCLAIMED_SECONDS 30U
#define PROBE_PEER_UNCLAIMED 3
#define PROBE_PEER_SWITCH 4
/* The peer's announced schedules during a session, with how often each was seen
 * and rejected by the follower: which shapes a sender uses that we cannot follow. */
#define PC_SCHEDULES_KEPT 6
struct schedule_seen { char key[96]; unsigned seen, rejected; };
static void schedule_note(struct schedule_seen *kept, size_t *count, const uint8_t *frame, size_t n, int rejected) {
    char key[96];
    if (pc_awdl_schedule_key(frame, n, key, sizeof(key))) return;
    for (size_t i = 0; i < *count; i++)
        if (!strcmp(kept[i].key, key)) { kept[i].seen++; kept[i].rejected += rejected ? 1U : 0U; return; }
    if (*count >= PC_SCHEDULES_KEPT) return;
    snprintf(kept[*count].key, sizeof(kept[*count].key), "%s", key);
    kept[*count].seen = 1; kept[*count].rejected = rejected ? 1U : 0U;
    (*count)++;
}

static int probe_run(const char *name, const uint8_t peer[6], unsigned seconds, const char *path, unsigned options,
                     uint16_t udp_port, const uint8_t token[16]) {
    int follow = !!(options & PC_PROBE_FOLLOW), mdns = !!(options & PC_PROBE_MDNS);
    int neighbor = !!(options & PC_PROBE_NEIGHBOR);
    int mdns_group = !!(options & PC_PROBE_MDNS_GROUP);
    unsigned rate = options & PC_PROBE_OFDM ? 24 : 2; /* radiotap units: 500 kbit/s */
    int unicast_follow = !!(options & PC_PROBE_UNICAST_FOLLOW);
    int primary_identity = !!(options & PC_PROBE_PRIMARY_IDENTITY);
    int service = !!(options & PC_PROBE_SERVICE);
    int tcp_service = !!(options & PC_PROBE_TCP_SERVICE);
    int rtsp_service = !!(options & PC_PROBE_RTSP_SERVICE);
    int native_control = !!(options & PC_PROBE_NATIVE_CONTROL);
    if (!native_control) return 2;
    int media_60s = !!(options & PC_PROBE_MEDIA_60S);
    int media_10m = !!(options & PC_PROBE_MEDIA_10M);
    int hold = !!(options & PC_PROBE_MEDIA_HOLD);
    /* Limits sized for ten minutes grow with a longer product session. */
    unsigned scale = hold && seconds >= 600 ? seconds / 600U : 1U;
    const char *awdl_profile = getenv("PICAST_AWDL_PROFILE");
    if (awdl_profile) {
        const char *named = strstr(awdl_profile, "gaps");
        int gaps = !named ? 0 : named[4] == '1' ? 1 : named[4] == '2' ? 2 : 3;
        int solo = strstr(awdl_profile, "nosolo") == NULL;
        pc_awdl_follow_set_profile(gaps, solo);
        printf("{\"event\":\"awdl_profile\",\"gaps\":%d,\"solo\":%d}\n", gaps, solo);
    }
    unsigned native_limit = media_10m ? (hold ? PC_PROBE_HOLD_SECONDS : 600U) : media_60s ? 60U : 20U;
    size_t tcp_packet_limit=media_10m ? (size_t)262144U * scale : TCP_PACKET_LIMIT;
    if(hold && !media_10m)return 2;
    if(media_10m && (media_60s || !native_control || (hold ? seconds<600 : seconds!=600)))return 2;
    if (media_60s && (!native_control || seconds != 60)) return 2;
    if (native_control && (!rtsp_service || !name || strcmp(name,"picastmon") || seconds>native_limit)) return 2;
    if ((rtsp_service && !tcp_service) || (tcp_service && (!service || seconds > (native_control ? native_limit : 8U))) || (options & ~65535U) || (service && (!follow || udp_port != 37000 || (options & PC_PROBE_GROUP_REPLIES))) || (primary_identity && (!follow || !name || strcmp(name, "picastmon"))) || (mdns_group && (!mdns || !follow)) || ((options & PC_PROBE_GROUP_REPLIES) && (!follow || udp_port != 37000)) || (neighbor && (!follow || mdns || udp_port)) || (unicast_follow && !follow) || (udp_port && (mdns || udp_port < 1024 || !token))) return 2;
    int fd = -1, rc = 1, signals_set = 0;
    FILE *pcap = NULL; struct pc_trace trace={0};
    struct sigaction oldint = {0}, oldterm = {0}, action = {0};
    uint8_t own[6], random[10];
    size_t attempts = 0, replies = 0, peer_actions = 0, packets = 0, announcements = 0, window_skips = 0;
    size_t peer_rejections = 0; uint64_t max_rx_queue_us = 0;
    struct schedule_seen schedules[PC_SCHEDULES_KEPT]; size_t schedule_count = 0;
    struct pc_awdl_peer follower = {0}; struct pc_rx_clock rx_clock = {0};
    struct echo_queue echo = {0}; uint16_t wire_sequence = 0;
    struct pc_tcp_diag tcp = {.tun=-1, .listener=-1, .client=-1};
    if (!name || !peer || !path || seconds < 1 || seconds > (media_10m ? native_limit : media_60s ? 60U : 30U) || strlen(name) >= IFNAMSIZ) return 2;
    fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(3));
    if (fd < 0) { perror("IP probe socket"); goto done; }
    struct ifreq request = {0};
    memcpy(request.ifr_name, name, strlen(name) + 1);
    if (ioctl(fd, SIOCGIFHWADDR, &request)) { perror("monitor MAC"); goto done; }
    if (request.ifr_hwaddr.sa_family != 803) { fputs("IP probe requires existing radiotap monitor interface\n", stderr); goto done; }
    memcpy(own, request.ifr_hwaddr.sa_data, 6);
    if (primary_identity) {
        struct ifreq primary = {0};
        memcpy(primary.ifr_name, "wlan0", 6);
        if (ioctl(fd, SIOCGIFHWADDR, &primary) || primary.ifr_hwaddr.sa_family != 1) {
            fputs("Owned primary radio address unavailable\n", stderr); goto done;
        }
        memcpy(own, primary.ifr_hwaddr.sa_data, 6);
        printf("{\"event\":\"primary_wire_identity_selected\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"interface_mac_changed\":false}\n",
               own[0], own[1], own[2], own[3], own[4], own[5]);
    }
    if (!memcmp(own, peer, 6)) { fputs("IP probe target must be a different owned peer\n", stderr); goto done; }
    int entropy = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (entropy < 0) { perror("probe entropy"); goto done; }
    ssize_t got_random = read(entropy, random, sizeof(random));
    close(entropy);
    if (got_random != (ssize_t)sizeof(random)) { fputs("Probe entropy unavailable\n", stderr); goto done; }
    uint16_t id = (uint16_t)(random[0] | (uint16_t)random[1] << 8);
    uint8_t ip[128];
    if ((udp_port ? pc_udp_build(own, peer, udp_port, id, 1, token, ip) :
         mdns ? pc_mdns_build(own, peer, id, ip) : pc_echo_build(own, peer, id, 1, random + 2, ip)) != PC_OK) {
        fputs("Invalid own or peer MAC\n", stderr); goto done;
    }
    if (pc_awdl_peer_init(&follower, own, peer) != PC_OK) goto done;
    struct probe_request probe = {.own = own, .peer = peer, .nonce = random + 2, .id = id, .rate = rate, .tcp_packet_limit=tcp_packet_limit, .mdns = mdns, .mdns_group = mdns_group, .service = service, .tcp_service = tcp_service, .neighbor = neighbor, .udp_port = udp_port, .token = token, .wire_sequence = &wire_sequence, .legacy = !!(options & PC_PROBE_LEGACY_DATA), .group_replies = !!(options & PC_PROBE_GROUP_REPLIES)};
    unsigned index = if_nametoindex(name);
    if (!index) { perror("probe ifindex"); goto done; }
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = (int)index, .sll_halen = 6};
    memcpy(address.sll_addr, peer, 6);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) { perror("probe bind"); goto done; }
    /* /dev/null: no recording (the product); anything else must be a new file. */
    int output = !strcmp(path, "/dev/null") ? open(path, O_WRONLY | O_CLOEXEC)
                                            : open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output < 0) { perror("new probe PCAP"); goto done; }
    pcap = fdopen(output, "wb");
    if (!pcap) { close(output); goto done; }
    /* Preserve complete records in the kernel even if the firmware kills the
     * process before fclose; avoid synchronous SD writes inside the radio scheduler. */
    if (setvbuf(pcap, NULL, _IONBF, 0)) goto done;
    if (pc_trace_init(&trace,pcap,64U*1024U*1024U,media_10m)!=PC_OK)goto done;
    action.sa_handler = stop; sigemptyset(&action.sa_mask); stopped = 0;
    sigaction(SIGINT, &action, &oldint); sigaction(SIGTERM, &action, &oldterm); signals_set = 1;
    if (tcp_service && pc_tcp_diag_open(&tcp, own, peer, token)) { perror("isolated TCP endpoint"); goto done; }
    if (tcp_service) probe.public_key=tcp.control.identity_public;
    tcp.rtsp = rtsp_service; tcp.native_control = native_control;
    if(media_10m){tcp.media.packet_limit=30000U*scale;tcp.media.byte_limit=(size_t)1024U*1024U*1024U*scale;tcp.control_message_limit=2048U*scale;}
    double started = mono(), deadline = started + seconds, last_send = -1;
    double last_peer_action = started;
    double last_health = started; int last_rejection = 0; uint64_t health_rx_queue_us = 0;
    struct rusage usage_start = {0};
    int usage_available = getrusage(RUSAGE_SELF, &usage_start) == 0;
    rc = 0;
    double farewell_until = 0;
    int final_rc = 0;
    double last_control_at = started, last_timing_at = started;
    size_t last_messages = 0; unsigned last_timing_valid = 0;
    for (;;) {
        /* Without this the sender only notices through its own timeout and keeps
         * showing an active session long after the picture is gone. */
        if (!farewell_until && (stopped || mono() >= deadline)) {
            if (!tcp_service || !tcp.native_control) break;
            printf("{\"event\":\"receiver_hangup\",\"reason\":\"%s\"}\n", stopped ? "stopped" : "deadline");
            pc_tcp_diag_hangup(&tcp);
            farewell_until = mono() + FAREWELL_SECONDS;
        }
        if (farewell_until && mono() >= farewell_until) {
            if (final_rc) rc = final_rc;
            break;
        }
        /* An iPhone that closed its menu or left stops all AWDL traffic. Hand
         * back to the supervisor, which listens for the next sender. */
        if (media_10m && !farewell_until && mono() - last_peer_action > PEER_IDLE_SECONDS) {
            printf("{\"event\":\"peer_idle_exit\",\"idle_seconds\":%u}\n", PEER_IDLE_SECONDS);
            break;
        }
        /* Long runs outlast the bounded trace, so stalls need their own record. */
        if (media_10m && mono() - last_health >= HEALTH_SECONDS) {
            last_health = mono();
            printf("{\"event\":\"health\",\"t\":%.1f,\"packets\":%zu,\"peer_actions\":%zu,\"peer_idle_ms\":%.0f,\"rejections\":%zu,\"last_rejection\":%d,\"window_skips\":%zu,\"phase\":%u,\"resyncs\":%u,\"master_changes\":%u,\"tx_queued\":%zu,\"tcp_sent\":%zu,\"tcp_dropped\":%zu,\"rx_queue_us\":%llu",
                   last_health - started, packets, peer_actions, (last_health - last_peer_action) * 1000, peer_rejections, last_rejection, window_skips, follower.phase, follower.resyncs, follower.master_changes, echo.count, echo.tcp_sent, echo.tcp_dropped, (unsigned long long)health_rx_queue_us);
            if (tcp.media_initialized)
                printf(",\"video_packets\":%u,\"audio_lost\":%u,\"audio_late\":%u,\"timing_valid\":%u", tcp.media.video_packets, tcp.media.audio.lost, tcp.media.audio.late_dropped, tcp.media.timing_valid);
            printf("}\n");
            health_rx_queue_us = 0;
        }
        /* Nobody connected: this may be the wrong one of several nearby iOS
         * devices, and only one peer can be followed at a time. */
        if (media_10m && !tcp.connections && mono() - started > PEER_UNCLAIMED_SECONDS) {
            printf("{\"event\":\"peer_unclaimed_exit\",\"unclaimed_seconds\":%u}\n", PEER_UNCLAIMED_SECONDS);
            rc = PROBE_PEER_UNCLAIMED;
            break;
        }
        /* A stuck session must not keep the receiver busy and its PIN on screen.
         * Starting over also gives other devices a turn. */
        if (media_10m && tcp_service && tcp.native_control && !farewell_until) {
            double at = mono();
            int mirroring = tcp.media_initialized && tcp.media.phase >= 2;
            if (tcp.messages != last_messages) { last_messages = tcp.messages; last_control_at = at; }
            if (!mirroring || (tcp.media_initialized && tcp.media.timing_valid != last_timing_valid)) {
                if (tcp.media_initialized) last_timing_valid = tcp.media.timing_valid;
                last_timing_at = at;
            }
            const char *stalled = tcp.connections && !mirroring && at - last_control_at > CONTROL_STALL_SECONDS ? "control" :
                                  mirroring && at - last_timing_at > TIMING_STALL_SECONDS ? "timing" : NULL;
            if (stalled) {
                printf("{\"event\":\"receiver_hangup\",\"reason\":\"%s_stall\"}\n", stalled);
                pc_tcp_diag_hangup(&tcp);
                farewell_until = at + FAREWELL_SECONDS;
                final_rc = PROBE_PEER_UNCLAIMED;
            }
        }
        if (tcp_service) {
            if (!farewell_until && pc_tcp_diag_step(&tcp)) {
                fputs("TCP diagnostic stream failure\n", stderr);
                if (!tcp.native_control) { rc = 1; break; }
                final_rc = 1; /* rc stays 0 here: a set rc ends the loop at once. */
                printf("{\"event\":\"receiver_hangup\",\"reason\":\"failure\"}\n");
                pc_tcp_diag_hangup(&tcp);
                farewell_until = mono() + FAREWELL_SECONDS;
            }
            uint8_t kernel_ip[1501]; size_t kernel_n;
            int got = pc_tcp_diag_read(&tcp, kernel_ip, &kernel_n);
            if (got < 0) { rc = 1; break; }
            if (got == PC_OK) {
                if (echo.count == ECHO_QUEUE_LENGTH || echo.sent >= tcp_packet_limit) echo.tcp_dropped++;
                else {
                    struct echo_pending *pending = &echo.packets[(echo.head + echo.count) % ECHO_QUEUE_LENGTH];
                    memcpy(pending->ip, kernel_ip, kernel_n); pending->size = kernel_n;
                    pending->neighbor = 3; pending->expires_us = (uint64_t)(mono() * 1e6) + 2000000;
                    echo.count++;
                }
            }
        }
        uint64_t wake = UINT64_MAX;
        if (follow) {
            for (unsigned event = PC_PEER_PSF; event <= PC_PEER_MIF; event <<= 1) {
                uint64_t now = (uint64_t)(mono() * 1e6);
                uint8_t announcement[400] = {0, 0, 9, 0, 4, 0, 0, 0, 2}; size_t n;
                int planned = pc_awdl_peer_build(&follower, now, event, announcement + 9, sizeof(announcement) - 9, &n);
                if (planned == PC_OTHER) continue;
                if (planned != PC_OK || announcements >= (media_10m ? 12000U * scale : media_60s ? 1200U : 400U)) { rc = 1; break; }
                announcement[8] = (uint8_t)rate;
                if (unicast_follow) memcpy(announcement + 13, peer, 6);
                if (transmit(fd, &address, &trace, announcement, n + 9, &announcements) ||
                    pc_awdl_peer_mark_sent(&follower, now, event) != PC_OK) { rc = 1; break; }
            }
            if (rc) break;
            uint64_t now = (uint64_t)(mono() * 1e6);
            struct pc_awdl_plan plan;
            int planned = pc_awdl_peer_poll(&follower, now, &plan);
            if (planned != PC_OK && planned != PC_OTHER) { rc = 1; break; }
            if (planned == PC_OK) {
                wake = plan.next_wake_us;
                if (plan.available & PC_PEER_DATA) {
                    struct pc_awdl_plan checked;
                    uint64_t sent_at = (uint64_t)(mono() * 1e6);
                    if (pc_awdl_peer_poll(&follower, sent_at, &checked) == PC_OK && (checked.available & PC_PEER_DATA)) {
                        if (echo_send(&echo, &probe, sent_at, fd, &address, &trace)) { rc = 1; break; }
                        if (echo.count) wake = sent_at;
                    }
                }
                /* The 15-second DNS-SD records must stay fresh throughout a
                 * separately authorized 60-second media trial. Ten initial
                 * announcements alone expire while PIN/setup is in flight. */
                size_t request_limit = service && (media_60s || media_10m) ? seconds : 10U;
                if (attempts < request_limit && (plan.available & PC_PEER_DATA)) {
                    double interval = mdns_group || service ? 1.0 : 0.1;
                    if (last_send < 0 || mono() - last_send >= interval) {
                        int sent = request_send(&probe, fd, &address, &trace, &attempts, &follower);
                        if (sent < 0) { rc = 1; break; }
                        if (!sent) last_send = mono();
                    }
                    if (last_send >= 0) {
                        uint64_t next_request = (uint64_t)((last_send + interval) * 1e6);
                        if (next_request > now && next_request < wake) wake = next_request;
                    }
                }
            }
        }
        struct pollfd fds[4] = {{.fd=fd, .events=POLLIN}, {.fd=tcp.tun, .events=POLLIN},
            {.fd=tcp.client<0 ? tcp.listener : -1, .events=POLLIN}, {.fd=(tcp.messages < (tcp.control_message_limit ? tcp.control_message_limit : tcp.native_control ? 16U : 3U) || tcp.tx_n) ? tcp.client : -1, .events=POLLIN}};
        if (tcp.tx_n) fds[3].events |= POLLOUT;
        double remaining = ((farewell_until ? farewell_until : deadline) - mono()) * 1000;
        int wait_ms = remaining > 250 ? 250 : remaining > 0 ? (int)remaining + 1 : 0;
        if(tcp_service && tcp.media_initialized && tcp.media.phase>=1 && wait_ms>2)wait_ms=2;
        if (follow && wake != UINT64_MAX) {
            uint64_t now = (uint64_t)(mono() * 1e6);
            uint64_t until_wake = wake > now ? (wake - now + 999) / 1000 : 0;
            if (until_wake < (uint64_t)wait_ms) wait_ms = (int)until_wake;
        }
        int ready = poll(fds, tcp_service ? 4 : 1, wait_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) { rc = 1; break; }
        if (!ready || !(fds[0].revents & POLLIN)) continue;
        uint8_t packet[65535];
        ssize_t got = recv(fd, packet, sizeof(packet), MSG_TRUNC);
        double received_at = mono();
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (got < 0) { perror("IP probe recv"); rc = 1; break; }
        if ((size_t)got > sizeof(packet)) continue;
        packets++;
        if (record(&trace, packet, (size_t)got)) { fputs("Probe PCAP write/limit failure\n", stderr); rc = 1; break; }
        struct pc_radiotap_view view;
        if (pc_radiotap_parse(packet, (size_t)got, &view) != PC_OK) continue;
        const uint8_t *frame = view.frame; size_t n = view.frame_size;
        uint64_t host_us = (uint64_t)(received_at * 1e6), observed_us = host_us;
        if (follow && view.has_tsft) {
            uint32_t resets = rx_clock.resets;
            if (pc_rx_clock_map(&rx_clock, view.tsft_us, host_us, &observed_us) != PC_OK) continue;
            if (rx_clock.resets != resets) { fputs("Firmware RX clock reset; stopping follower transmission\n", stderr); rc = 1; break; }
            if (host_us - observed_us > max_rx_queue_us) max_rx_queue_us = host_us - observed_us;
            if (host_us - observed_us > health_rx_queue_us) health_rx_queue_us = host_us - observed_us;
        }
        uint8_t knocking[6] = {0};
        struct reply_context received = {.own = own, .peer = peer, .nonce = random + 2,
            .id = id, .attempts = attempts, .mdns = mdns, .mdns_group = mdns_group, .neighbor = neighbor, .udp_port = udp_port, .token = token, .echo = follow ? &echo : NULL, .observed_us = host_us, .tcp = tcp_service ? &tcp : NULL, .knocking = media_10m ? knocking : NULL};
        (void)pc_awdl_data_visit(frame, n, check_reply, &received);
        replies += received.observations;
        /* Only one peer can be followed. A connecting device takes over unless
         * someone is mirroring; its SYN retries reach the next process. */
        if (knocking[0] != 0 || knocking[1] != 0 || knocking[2] != 0 || knocking[3] != 0 || knocking[4] != 0 || knocking[5] != 0) {
            if (!(knocking[0] & 1) && !(tcp.media_initialized && tcp.media.phase >= 1)) {
                printf("{\"event\":\"peer_switch_request\",\"peer\":\"%02x:%02x:%02x:%02x:%02x:%02x\"}\n", knocking[0], knocking[1], knocking[2], knocking[3], knocking[4], knocking[5]);
                rc = PROBE_PEER_SWITCH;
                break;
            }
        }
        struct pc_awdl a;
        if (pc_awdl_parse(frame, n, &a, NULL, NULL) != PC_OK || memcmp(a.source, peer, 6)) continue;
        peer_actions++;
        last_peer_action = mono();
        if (follow) {
            int observed = pc_awdl_peer_observe(&follower, frame, n, observed_us);
            if (observed != PC_OK && observed != PC_OTHER) { peer_rejections++; last_rejection = observed; }
            schedule_note(schedules, &schedule_count, frame, n, observed != PC_OK && observed != PC_OTHER);
            struct pc_awdl_plan plan;
            if (pc_awdl_peer_poll(&follower, host_us, &plan) != PC_OK || !(plan.available & PC_PEER_DATA)) window_skips++;
            continue; /* next event-loop tick drives announcements and requests */
        }
        if (attempts >= 10 || (last_send >= 0 && mono() - last_send < 0.1)) continue;
        double elapsed_us = (mono() - received_at) * 1e6;
        if (elapsed_us < 0 || elapsed_us > 65536 ||
            pc_awdl_data_window(frame, n, (uint32_t)elapsed_us) != PC_OK) {
            window_skips++; continue;
        }
        if (request_send(&probe, fd, &address, &trace, &attempts, NULL)) { rc = 1; break; }
        last_send = mono();
    }
    struct rusage usage_end = {0};
    if (usage_available && !getrusage(RUSAGE_SELF, &usage_end)) {
        long long user_us = (long long)(usage_end.ru_utime.tv_sec-usage_start.ru_utime.tv_sec)*1000000 + usage_end.ru_utime.tv_usec-usage_start.ru_utime.tv_usec;
        long long system_us = (long long)(usage_end.ru_stime.tv_sec-usage_start.ru_stime.tv_sec)*1000000 + usage_end.ru_stime.tv_usec-usage_start.ru_stime.tv_usec;
        /* Linux ru_maxrss is KiB, for the process lifetime; CPU is the loop
         * delta. No procfs scan or resource query in the radio hot path. */
        printf("{\"event\":\"probe_runtime_summary\",\"requested_seconds\":%u,\"elapsed_ms\":%.3f,\"user_cpu_us\":%lld,\"system_cpu_us\":%lld,\"process_peak_rss_kib\":%ld,\"interrupted\":%s,\"loop_error\":%s}\n",seconds,(mono()-started)*1000,user_us,system_us,usage_end.ru_maxrss,stopped ? "true" : "false",rc ? "true" : "false");
    }
    if (tcp_service) printf("{\"event\":\"kernel_tcp_diagnostic_summary\",\"validated_messages\":%zu,\"injected_packets\":%zu,\"kernel_packets\":%zu,\"submitted_packets\":%zu,\"dropped_packets\":%zu}\n", tcp.messages, tcp.injected, tcp.kernel_packets, echo.tcp_sent, echo.tcp_dropped);
    printf("{\"event\":\"owned_udp_responder_summary\",\"received\":%zu,\"sent\":%zu,\"dropped\":%zu}\n", echo.udp_received, echo.udp_sent, echo.udp_dropped);
    if (service) printf("{\"event\":\"diagnostic_service_announcement_summary\",\"host_submissions\":%zu,\"ttl_seconds\":15,\"airplay_receiver\":false}\n", attempts);
    for (size_t i = 0; i < schedule_count; i++)
        printf("{\"event\":\"peer_schedule_summary\",\"schedule\":\"%s\",\"seen\":%u,\"rejected\":%u}\n", schedules[i].key, schedules[i].seen, schedules[i].rejected);
    printf("{\"event\":\"ip_probe_summary\",\"packets_received\":%zu,\"peer_actions\":%zu,\"echo_requests_accepted\":%zu,"
           "\"verified_echo_reply_observations\":%zu,\"mdns_queries_accepted\":%zu,\"verified_mdns_reply_observations\":%zu,"
           "\"peer_announcements\":%zu,\"data_window_skips\":%zu,\"tx_rate_500kbps\":%u,\"unicast_follow\":%s,\"time_driven_follow\":%s,\"legacy_data\":%s,\"peer_phase\":%u,\"peer_rejections\":%zu,\"clock_resyncs\":%u,\"holdover_reacquisitions\":%u,\"master_changes\":%u,\"clock_discontinuities\":%u,\"tsft_samples\":%u,\"maximum_estimated_rx_queue_us\":%llu,\"udp_probes_accepted\":%zu,\"verified_udp_reply_observations\":%zu,\"owned_echo_requests_received\":%zu,\"owned_echo_replies_sent\":%zu,\"owned_echo_replies_dropped\":%zu,\"owned_neighbor_requests_received\":%zu,\"owned_neighbor_replies_sent\":%zu,\"owned_neighbor_replies_dropped\":%zu,\"neighbor_solicitations_accepted\":%zu,\"verified_neighbor_reply_observations\":%zu,\"airplay_receiver\":false,\"milestone_2\":false}\n",
           packets, peer_actions, (mdns || udp_port || neighbor) ? 0 : attempts, (mdns || udp_port || neighbor) ? 0 : replies, mdns ? attempts : 0, mdns ? replies : 0, announcements, window_skips, rate, unicast_follow ? "true" : "false",
           follow ? "true" : "false", probe.legacy ? "true" : "false", follower.phase, peer_rejections, follower.resyncs, follower.holdover_reacquisitions, follower.master_changes, follower.clock_discontinuities, rx_clock.samples,
           (unsigned long long)max_rx_queue_us, udp_port && !service ? attempts : 0, udp_port && !service ? replies : 0, echo.received, echo.sent - echo.neighbor_sent - echo.udp_sent - echo.tcp_sent, echo.dropped, echo.neighbor_received, echo.neighbor_sent, echo.neighbor_dropped, neighbor ? attempts : 0, neighbor ? replies : 0);
done:
    if (tcp_service) pc_tcp_diag_close(&tcp);
    if (signals_set) { sigaction(SIGINT, &oldint, NULL); sigaction(SIGTERM, &oldterm, NULL); }
    if(trace.stream)printf("{\"event\":\"diagnostic_trace_summary\",\"bytes_retained\":%zu,\"records_skipped\":%zu,\"soft_limit\":%s}\n",trace.bytes,trace.skipped,trace.soft_limit ? "true" : "false");
    if (pcap && fclose(pcap)) { perror("probe PCAP close"); rc = 1; }
    if (fd >= 0) close(fd);
    return rc;
}
int pc_ip_probe(const char *interface, const uint8_t peer[6], unsigned seconds, const char *path, unsigned options) {
    return probe_run(interface, peer, seconds, path, options, 0, NULL);
}
int pc_udp_probe(const char *interface, const uint8_t peer[6], unsigned seconds, const char *path,
                  unsigned options, uint16_t port, const uint8_t token[16]) {
    if (port < 1024 || !token || (options & PC_PROBE_MDNS)) return 2;
    return probe_run(interface, peer, seconds, path, options, port, token);
}
#else
int pc_ip_probe(const char *interface, const uint8_t peer[6], unsigned seconds, const char *path, unsigned options) {
    (void)interface; (void)peer; (void)seconds; (void)path; (void)options;
    fputs("Live IP probe requires Linux\n", stderr); return 1;
}
int pc_udp_probe(const char *interface, const uint8_t peer[6], unsigned seconds, const char *path,
                  unsigned options, uint16_t port, const uint8_t token[16]) {
    (void)port; (void)token;
    return pc_ip_probe(interface, peer, seconds, path, options);
}
#endif

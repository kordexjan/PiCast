#include "picast.h"
#include <stdio.h>

#ifdef __linux__
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct request { uint8_t data[256]; size_t size; };
static int64_t millis(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void init(struct request *r, uint16_t family, uint8_t cmd, uint32_t seq, int ack) {
    memset(r, 0, sizeof(*r));
    struct nlmsghdr h = {.nlmsg_type = family, .nlmsg_flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0), .nlmsg_seq = seq};
    struct genlmsghdr g = {.cmd = cmd, .version = 1};
    memcpy(r->data, &h, sizeof(h));
    memcpy(r->data + NLMSG_HDRLEN, &g, sizeof(g));
    r->size = NLMSG_HDRLEN + GENL_HDRLEN;
}
static int attr_add(struct request *r, uint16_t type, const void *data, size_t size) {
    size_t total = NLA_HDRLEN + size, aligned = (total + 3) & ~(size_t)3;
    if (total > UINT16_MAX || aligned > sizeof(r->data) - r->size) return -1;
    struct nlattr a = {.nla_len = (uint16_t)total, .nla_type = type};
    memcpy(r->data + r->size, &a, sizeof(a));
    memcpy(r->data + r->size + NLA_HDRLEN, data, size);
    r->size += aligned;
    return 0;
}
static int send_request(int fd, struct request *r) {
    uint32_t size = (uint32_t)r->size;
    memcpy(r->data, &size, sizeof(size));
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    if (sendto(fd, r->data, r->size, 0, (struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)r->size) {
        perror("netlink send"); return -1;
    }
    return 0;
}
static ssize_t receive(int fd, uint8_t *data, size_t size, int64_t deadline) {
    for (;;) {
        int64_t remaining = deadline - millis();
        if (remaining <= 0) return 0;
        struct pollfd pollfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pollfd, 1, (int)remaining);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return rc;
        if (!(pollfd.revents & POLLIN)) return -1;
        struct sockaddr_nl sender = {0}; socklen_t len = sizeof(sender);
        ssize_t got = recvfrom(fd, data, size, MSG_TRUNC, (struct sockaddr *)&sender, &len);
        if (got < 0) { if (errno == EINTR) continue; return -1; }
        if ((size_t)got > size) { fputs("Truncated netlink datagram\n", stderr); return -1; }
        if (len != sizeof(sender) || sender.nl_pid != 0) continue;
        return got;
    }
}
static int transaction(int fd, struct request *r, uint32_t seq, uint8_t *reply, size_t *reply_size) {
    if (send_request(fd, r)) return -1;
    int64_t deadline = millis() + 3000;
    for (;;) {
        uint8_t data[8192];
        ssize_t got = receive(fd, data, sizeof(data), deadline);
        if (got <= 0) { fputs("Netlink reply timed out or failed\n", stderr); return -1; }
        size_t pos = 0;
        while ((size_t)got - pos >= NLMSG_HDRLEN) {
            struct nlmsghdr h; memcpy(&h, data + pos, sizeof(h));
            if (h.nlmsg_len < NLMSG_HDRLEN || h.nlmsg_len > (size_t)got - pos) return -1;
            if (h.nlmsg_seq == seq) {
                if (h.nlmsg_type == NLMSG_ERROR) {
                    if (h.nlmsg_len < NLMSG_HDRLEN + sizeof(int32_t)) return -1;
                    int32_t error; memcpy(&error, data + pos + NLMSG_HDRLEN, sizeof(error));
                    if (error) { fprintf(stderr, "nl80211 rejected request: %s (%d)\n", strerror(-error), error); return -1; }
                    *reply_size = 0; return 0;
                }
                if (h.nlmsg_len > *reply_size) return -1;
                memcpy(reply, data + pos, h.nlmsg_len); *reply_size = h.nlmsg_len;
                return 0;
            }
            size_t step = ((size_t)h.nlmsg_len + 3) & ~(size_t)3;
            if (step > (size_t)got - pos) return -1;
            pos += step;
        }
    }
}

static int connect_family(uint16_t *family) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) { perror("NETLINK_GENERIC"); return -1; }
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) { perror("netlink bind"); goto done; }
    struct request r;
    init(&r, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, 0);
    const char family_name[] = "nl80211";
    if (attr_add(&r, CTRL_ATTR_FAMILY_NAME, family_name, sizeof(family_name))) goto done;
    uint8_t reply[8192]; size_t size = sizeof(reply);
    if (transaction(fd, &r, 1, reply, &size) || size < NLMSG_HDRLEN + GENL_HDRLEN) goto done;
    const uint8_t *value; size_t n;
    if (pc_netlink_attr(reply + NLMSG_HDRLEN + GENL_HDRLEN, size - NLMSG_HDRLEN - GENL_HDRLEN,
                  CTRL_ATTR_FAMILY_ID, &value, &n) || n != 2) goto done;
    memcpy(family, value, sizeof(*family));
    return fd;
done:
    close(fd); return -1;
}

static int firmware_queries(const char *name, int kind) {
    if (kind == 5 && strcmp(name,"picastmon")) return 2;
    unsigned index = if_nametoindex(name);
    if (!index) { perror("interface lookup"); return 1; }
    uint16_t family;
    int fd = connect_family(&family);
    if (fd < 0) return 1;
    /* No arbitrary ioctl/value input. The sole fixed write is MPC=0 on our
     * qualified candidate in active picastmon mode, after readback checks. */
    static const struct { const char *name; uint32_t cmd, size; const char *variable; } queries[] = {
        {"monitor", 107, 4, NULL}, {"cap", 262, 768, "cap"}, {"ver", 262, 256, "ver"},
        {"packet_counters", 137, 20, NULL}, {"current_address", 262, 32, "cur_etheraddr"},
        {"unused", 0, 0, NULL},     /* keeps the indexes below */
        {"power_management", 85, 4, NULL}, {"minimum_power_consumption", 262, 4, "mpc"},
        {"monitor_mpc_disabled", 263, 8, "mpc"}
    };
    int result = 0;
    int monitor_ready=0, candidate_ready=0;
    size_t first = kind == 4 ? 6 : kind == 3 ? 5 : kind == 2 ? 4 : kind == 1 ? 3 : 0;
    size_t end_query = kind == 5 ? 9 : kind == 4 ? 8 : kind == 3 ? 6 : kind == 2 ? 5 : kind == 1 ? 4 : 3;
    for (size_t i = first; i < end_query; i++) {
        if(kind==5 && i>=3 && i<8)continue;
        int fixed_write=kind==5 && i==8;
        if(fixed_write && (result || !monitor_ready || !candidate_ready)){
            fputs("MPC test requires qualified candidate firmware and monitor mode2\n",stderr);result=1;break;
        }
        struct request r;
        uint32_t seq = (uint32_t)i + 2, ifindex = index, oui = 0x001018, subcmd = 1;
        init(&r, family, NL80211_CMD_VENDOR, seq, 0);
        uint32_t header[] = {queries[i].cmd, queries[i].size, 20, fixed_write ? 1U : 0U, 0x14e46c77};
        uint8_t vendor[52] = {0};
        memcpy(vendor, header, sizeof(header));
        size_t parameter_size = queries[i].variable ? strlen(queries[i].variable) + 1 : 4;
        if (parameter_size > sizeof(vendor) - 20) { result = 1; break; }
        if (queries[i].variable) memcpy(vendor + 20, queries[i].variable, strlen(queries[i].variable)+1);
        if(fixed_write)parameter_size=8; /* mpc\0 followed by the fixed u32 zero */
        if (attr_add(&r, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex)) ||
            attr_add(&r, NL80211_ATTR_VENDOR_ID, &oui, sizeof(oui)) ||
            attr_add(&r, NL80211_ATTR_VENDOR_SUBCMD, &subcmd, sizeof(subcmd)) ||
            attr_add(&r, NL80211_ATTR_VENDOR_DATA, vendor, 20 + parameter_size)) { result = 1; break; }
        uint8_t reply[8192]; size_t size = sizeof(reply);
        if (transaction(fd, &r, seq, reply, &size) || size < NLMSG_HDRLEN + GENL_HDRLEN) { result = 1; continue; }
        struct genlmsghdr g; memcpy(&g, reply + NLMSG_HDRLEN, sizeof(g));
        const uint8_t *area, *value, *length; size_t area_size, n, length_size;
        if (g.cmd != NL80211_CMD_VENDOR ||
            pc_netlink_attr(reply + NLMSG_HDRLEN + GENL_HDRLEN, size - NLMSG_HDRLEN - GENL_HDRLEN,
                            NL80211_ATTR_VENDOR_DATA, &area, &area_size) ||
            pc_netlink_attr(area, area_size, 2, &value, &n) ||
            pc_netlink_attr(area, area_size, 1, &length, &length_size) || length_size != 2) {
            fputs("Malformed vendor reply\n", stderr); result = 1; continue;
        }
        uint16_t declared; memcpy(&declared, length, sizeof(declared));
        if (declared != n || n != queries[i].size) {
            fputs("Unexpected vendor reply length\n", stderr); result = 1; continue;
        }
        printf("{\"event\":\"firmware_info\",\"query\":\"%s\",\"read_only\":%s,", queries[i].name,fixed_write ? "false" : "true");
        if (kind == 4) {
            uint32_t mode=(uint32_t)value[0] | (uint32_t)value[1]<<8 | (uint32_t)value[2]<<16 | (uint32_t)value[3]<<24;
            printf("\"value\":%u,",mode);
        }
        if (!i) {
            uint32_t mode = (uint32_t)value[0] | (uint32_t)value[1] << 8 |
                            (uint32_t)value[2] << 16 | (uint32_t)value[3] << 24;
            printf("\"monitor_mode\":%u,", mode);
            monitor_ready=mode==2;
        } else if (i < 3) {
            const uint8_t *end = memchr(value, 0, n);
            if (end) n = (size_t)(end - value);
            if(i==2){
                static const char marker[]="9.88.4.65 (nexmon.org: 68720406-picast-";
                for(size_t k=0;k+sizeof(marker)-1<=n;k++)
                    if(!memcmp(value+k,marker,sizeof(marker)-1))candidate_ready=1;
            }
        }
        if (kind == 2) n = 6;
        if (kind == 1) {
            const char *fields[] = {"rx_good", "rx_bad", "tx_good", "tx_bad", "rx_other_unicast"};
            for (size_t k = 0; k < 5; k++) {
                const uint8_t *p = value + 4 * k;
                uint32_t count = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
                printf("\"%s\":%u,", fields[k], count);
            }
        }
        printf("\"data_hex\":\"");
        for (size_t j = 0; j < n; j++) printf("%02x", value[j]);
        puts("\"}");
    }
    close(fd); return result;
}
/* Packet counters (a hung transmitter shows as failures only), power state (the
 * radio still answers) and keeping the monitor awake (no power saving while a
 * sender may call). Fixed queries only, never an address or a value from outside. */
int pc_firmware_counters(const char *name) { return firmware_queries(name, 1); }
int pc_firmware_power(const char *name) { return firmware_queries(name, 4); }
int pc_firmware_monitor_awake(const char *name) { return firmware_queries(name, 5); }
#else
static int no_radio(const char *interface) {
    (void)interface;
    fputs("Radio queries require Linux.\n", stderr); return 1;
}
int pc_firmware_counters(const char *interface) { return no_radio(interface); }
int pc_firmware_power(const char *interface) { return no_radio(interface); }
int pc_firmware_monitor_awake(const char *interface) { return no_radio(interface); }
#endif

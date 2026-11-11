#include "picast.h"
#include <stdio.h>

#if defined(__linux__)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop(int signum) { (void)signum; stopped = 1; }
static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static int wait_read(int fd, double deadline) {
    while (!stopped) {
        double ms = (deadline - now()) * 1000;
        if (ms <= 0) return 0;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int rc = poll(&p, 1, ms > INT_MAX ? INT_MAX : (int)ms + 1);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) return rc;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
        if (p.revents & POLLIN) return 1;
    }
    return 0;
}
static void signals(struct sigaction *oldint, struct sigaction *oldterm) {
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    stopped = 0;
    sigaction(SIGINT, &action, oldint); sigaction(SIGTERM, &action, oldterm);
}

int pc_capture(const char *name, unsigned seconds) {
    return pc_capture_to_file(name, seconds, NULL);
}

int pc_capture_to_file(const char *name, unsigned seconds, const char *path) {
    FILE *pcap = NULL;
    size_t written = 24;
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x0003));
    if (fd < 0) { perror("AF_PACKET (CAP_NET_RAW required)"); return 1; }
    struct ifreq req = {0};
    int rc = 1;
    if (strlen(name) >= sizeof(req.ifr_name)) goto done;
    memcpy(req.ifr_name, name, strlen(name) + 1);
    if (ioctl(fd, SIOCGIFHWADDR, &req)) { perror("interface type"); goto done; }
    int type = req.ifr_hwaddr.sa_family;
    /* ARPHRD_IEEE80211_RADIOTAP / ARPHRD_IEEE80211. Reject Ethernet WLAN. */
    if (type != 803 && type != 801) {
        fputs("Requires an existing monitor interface (radiotap or raw 802.11). No interface was changed.\n", stderr);
        goto done;
    }
    unsigned index = if_nametoindex(name);
    if (!index) { perror("if_nametoindex"); goto done; }
    struct sockaddr_ll addr = {.sll_family = AF_PACKET, .sll_protocol = htons(0x0003), .sll_ifindex = (int)index};
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) { perror("bind"); goto done; }
    if (path) {
        int output = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (output < 0) { perror("new PCAP file"); goto done; }
        pcap = fdopen(output, "wb");
        if (!pcap) { close(output); perror("PCAP stream"); goto done; }
        uint8_t header[24];
        if (pc_pcap_header(header, type == 803 ? 127 : 105) != PC_OK ||
            fwrite(header, 1, sizeof(header), pcap) != sizeof(header)) goto done;
    }
    struct sigaction oldint, oldterm;
    signals(&oldint, &oldterm);
    double deadline = now() + seconds;
    size_t packets = 0, matches = 0, data_count = 0, invalid = 0;
    rc = 0;
    int ready;
    while ((ready = wait_read(fd, deadline)) > 0) {
        uint8_t data[65535];
        ssize_t got = recv(fd, data, sizeof(data), MSG_TRUNC);
        if (got < 0) { if (errno == EINTR) continue; perror("recv"); rc = 1; break; }
        packets++;
        if ((size_t)got > sizeof(data)) { invalid++; continue; }
        if (pcap) {
            struct timespec timestamp;
            uint8_t record[16];
            if (written + 16 + (size_t)got > 64U * 1024 * 1024) {
                fputs("PCAP limit of 64 MiB reached\n", stderr); rc = 1; break;
            }
            if (clock_gettime(CLOCK_REALTIME, &timestamp) || timestamp.tv_sec < 0 ||
                (uint64_t)timestamp.tv_sec > UINT32_MAX ||
                pc_pcap_record(record, (uint32_t)timestamp.tv_sec, (uint32_t)(timestamp.tv_nsec / 1000), (size_t)got) != PC_OK ||
                fwrite(record, 1, sizeof(record), pcap) != sizeof(record) ||
                fwrite(data, 1, (size_t)got, pcap) != (size_t)got) {
                fputs("PCAP write failed\n", stderr); rc = 1; break;
            }
            written += 16 + (size_t)got;
        }
        const uint8_t *frame = data; size_t n = (size_t)got;
        int parsed = type == 803 ? pc_radiotap(data, n, &frame, &n) : PC_OK;
        if (parsed == PC_OK) {
            parsed = pc_print_awdl(frame, n);
            if (parsed == PC_OK) matches++;
            else if (parsed == PC_OTHER) {
                parsed = pc_print_awdl_data(frame, n);
                if (parsed == PC_OK) data_count++;
            }
        }
        if (parsed == PC_INVALID) invalid++;
        fflush(stdout);
    }
    if (ready < 0) { fputs("Capture socket failed\n", stderr); rc = 1; }
    printf("{\"event\":\"capture_summary\",\"packets\":%zu,\"awdl_actions\":%zu,"
           "\"awdl_data\":%zu,\"invalid\":%zu}\n", packets, matches, data_count, invalid);
    sigaction(SIGINT, &oldint, NULL); sigaction(SIGTERM, &oldterm, NULL);
done:
    if (pcap && fclose(pcap)) { perror("PCAP close"); rc = 1; }
    close(fd); return rc;
}

#else
int pc_capture(const char *interface, unsigned seconds) {
    (void)interface; (void)seconds;
    fputs("Live capture requires Linux; offline decoding works on this platform.\n", stderr);
    return 1;
}
int pc_capture_to_file(const char *interface, unsigned seconds, const char *path) {
    (void)path;
    return pc_capture(interface, seconds);
}
#endif

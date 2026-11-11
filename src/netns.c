#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "picast.h"
#include <stdio.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The receiver's own small network: a TUN device in a fresh network namespace
 * carries the sender's IPv6 packets to ordinary sockets there. No physical
 * interface or host route is ever changed. A child sets the namespace up and
 * passes its descriptors back, which keep the namespace alive. */
struct endpoint { int tun, udp, media[5]; unsigned index; };

static double monotonic(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void child_endpoint(int channel, unsigned which, ino_t host_namespace, const uint8_t own[6], int tcp) {
    struct stat ns;
    const char *stage = "unshare network namespace";
    if (unshare(CLONE_NEWNET) || stat("/proc/self/ns/net", &ns) || ns.st_ino == host_namespace) goto fail;
    stage = "open isolated TUN/UDP";
    int tun = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    int udp = socket(AF_INET6, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (tun < 0 || udp < 0) goto fail;
    struct ifreq interface = {0};
    memcpy(interface.ifr_name, "picast0", 8);
    interface.ifr_flags = IFF_TUN | IFF_NO_PI;
    stage = "create isolated TUN";
    if (ioctl(tun, TUNSETIFF, &interface)) goto fail;
    unsigned index = if_nametoindex(interface.ifr_name);
    if (!index) goto fail;
    /* This path refers to picast0 in this child's namespace, created above.
     * Suppress DAD only there; never change any host IPv6 sysctl. */
    int dad = open("/proc/sys/net/ipv6/conf/picast0/accept_dad", O_WRONLY | O_CLOEXEC);
    stage = "configure isolated DAD";
    if (dad < 0) goto fail;
    ssize_t set_dad = write(dad, "0\n", 2);
    close(dad);
    if (set_dad != 2) goto fail;
    if (tcp) {
        /* Leave headroom for AWDL/802.11/radiotap inside the monitor's
         * 1500-byte host submission limit. Linux advertises the matching
         * TCP MSS and segments both directions; never touch host interfaces. */
        stage = "configure isolated TCP MTU";
        interface.ifr_mtu=1280;
        if (ioctl(udp,SIOCSIFMTU,&interface)) goto fail;
    }
    stage = "activate isolated TUN";
    if (ioctl(udp, SIOCGIFFLAGS, &interface)) goto fail;
    interface.ifr_flags |= IFF_UP;
    if (ioctl(udp, SIOCSIFFLAGS, &interface)) goto fail;
    struct in6_ifreq assignment = {.ifr6_prefixlen = 64, .ifr6_ifindex = (int)index};
    pc_linklocal(own, assignment.ifr6_addr.s6_addr);
    stage = "assign isolated IPv6 address";
    if (ioctl(udp, SIOCSIFADDR, &assignment)) goto fail;
    struct sockaddr_in6 local = {.sin6_family = AF_INET6, .sin6_port = htons(which ? 37000 : 49152), .sin6_scope_id = index};
    local.sin6_addr = assignment.ifr6_addr;
    stage = "bind isolated UDP endpoint";
    /* IPv6 address activation is asynchronous even with DAD disabled. Wait
     * for actual bind readiness rather than treating ioctl success as ready. */
    double deadline = monotonic() + 2;
    while (bind(udp, (struct sockaddr *)&local, sizeof(local))) {
        if (errno != EADDRNOTAVAIL || monotonic() >= deadline) goto fail;
        struct timespec delay = {.tv_nsec = 10000000};
        nanosleep(&delay, NULL);
    }
    if (tcp && which && listen(udp, 1)) goto fail;
    int descriptors[7] = {tun, udp, -1, -1, -1, -1, -1};
    if (tcp==2) {
        for (unsigned i=0;i<5;i++) {
            int fd=socket(AF_INET6,(i>=2 ? SOCK_DGRAM : SOCK_STREAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
            descriptors[i+2]=fd;local.sin6_port=htons((uint16_t)(37001+i));
            stage="bind isolated media endpoint";
            if (fd<0 || bind(fd,(struct sockaddr *)&local,sizeof(local)) || (i<2 && listen(fd,1))) goto fail;
        }
    }
    size_t descriptor_bytes=(tcp==2 ? 7U : 2U)*sizeof(int);
    struct iovec io = {.iov_base = &index, .iov_len = sizeof(index)};
    union { struct cmsghdr alignment; uint8_t bytes[CMSG_SPACE(sizeof(descriptors))]; } control = {0};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = CMSG_SPACE(descriptor_bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(descriptor_bytes);
    memcpy(CMSG_DATA(c), descriptors, descriptor_bytes);
    stage = "pass isolated descriptors";
    if (sendmsg(channel, &message, MSG_NOSIGNAL) != (ssize_t)sizeof(index)) goto fail;
    _exit(0);
fail:
    perror(stage);
    _exit(1); /* Closing all child descriptors also destroys partial setup. */
}

static int endpoint_open_at(struct endpoint *out, unsigned which, ino_t host_namespace, const uint8_t own[6], int tcp) {
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel)) return -1;
    pid_t child = fork();
    if (child == 0) { close(channel[0]); child_endpoint(channel[1], which, host_namespace, own, tcp); }
    close(channel[1]);
    if (child < 0) { close(channel[0]); return -1; }
    int result = -1;
    struct pollfd p = {.fd = channel[0], .events = POLLIN};
    int ready;
    do { ready = poll(&p, 1, 5000); } while (ready < 0 && errno == EINTR);
    if (ready > 0 && (p.revents & POLLIN)) {
        unsigned index = 0;
        int descriptors[7] = {-1,-1,-1,-1,-1,-1,-1};
        size_t descriptor_bytes=(tcp==2 ? 7U : 2U)*sizeof(int);
        struct iovec io = {.iov_base = &index, .iov_len = sizeof(index)};
        union { struct cmsghdr alignment; uint8_t bytes[CMSG_SPACE(sizeof(descriptors))]; } control = {0};
        struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
        ssize_t received = recvmsg(channel[0], &message, MSG_CMSG_CLOEXEC);
        struct cmsghdr *c = CMSG_FIRSTHDR(&message);
        if (received == (ssize_t)sizeof(index) && index && !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) &&
            c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(descriptor_bytes)) {
            memcpy(descriptors, CMSG_DATA(c), descriptor_bytes);
            if (tcp==2) memcpy(out->media,descriptors+2,sizeof(out->media));
            out->tun = descriptors[0]; out->udp = descriptors[1]; out->index = index;
            result = 0;
        }
    }
    close(channel[0]);
    /* No unbounded wait, including failure before the descriptor handoff. */
    if (result) kill(child, SIGKILL);
    int status;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return result;
}


int pc_media_tun_open(const uint8_t own[6],int *tun,int *listener,int sockets[5]) {
    struct stat ns;struct endpoint e={.tun=-1,.udp=-1};
    if (!own || !tun || !listener || !sockets || stat("/proc/self/ns/net",&ns) ||
        endpoint_open_at(&e,1,ns.st_ino,own,2))return -1;
    *tun=e.tun;*listener=e.udp;memcpy(sockets,e.media,sizeof(e.media));return 0;
}
#else
int pc_media_tun_open(const uint8_t own[6],int *tun,int *listener,int sockets[5]) {
    (void)own;(void)tun;(void)listener;(void)sockets;return -1;
}
#endif

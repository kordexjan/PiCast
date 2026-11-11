#ifndef PICAST_TCP_H
#define PICAST_TCP_H
#include "picast.h"
#ifndef PC_TCP_MESSAGE_BYTES
#define PC_TCP_MESSAGE_BYTES 36
#endif
_Static_assert(PC_TCP_MESSAGE_BYTES>=36 && PC_TCP_MESSAGE_BYTES<=8192, "bounded TCP message size");
#include "picast_media.h"
#include "picast_control.h"
/* Bounded diagnostic only: one peer, one stream, three 36-byte nonce messages.
 * TCP sequencing, checksums, retransmission and congestion control are Linux's.
 * The descriptors hold a private namespace, destroyed when they are closed. */
struct pc_tcp_diag {
    size_t control_message_limit;
    int tun, listener, client;
    uint8_t own[6], peer[6], token[16], rx[8192], tx[8192];
    int rtsp, native_control;
    unsigned connections;
    int pin_cleared;
    int ui_blanked;
    struct pc_control control;
    int control_initialized;
    struct pc_media media;
    int media_initialized;
    size_t rx_n, tx_n, tx_offset, messages, injected, kernel_packets;
};
int pc_tcp_diag_open(struct pc_tcp_diag *d, const uint8_t own[6], const uint8_t peer[6], const uint8_t token[16]);
void pc_tcp_diag_close(struct pc_tcp_diag *d);
/* Ends the sender's TCP connections while the tunnel stays open, so the caller
 * can still carry the closing packets over the radio before pc_tcp_diag_close. */
void pc_tcp_diag_hangup(struct pc_tcp_diag *d);
int pc_tcp_diag_step(struct pc_tcp_diag *d);
int pc_tcp_diag_ingress(struct pc_tcp_diag *d, const uint8_t *ip, size_t n);
int pc_tcp_diag_read(struct pc_tcp_diag *d, uint8_t out[1501], size_t *n);
#endif

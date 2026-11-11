/* PiCast monitor admission policy for the BCM43436b0 firmware 9.88.4.65. GPL-3.0-or-later. */
#ifndef PICAST_MONITOR_PROFILE_H
#define PICAST_MONITOR_PROFILE_H
#define PC_MONITOR_MAX_FRAME 16384U

static inline int pc_monitor_packet_length_valid(int bytes) {
    return bytes >= 30 && (unsigned int)bytes <= PC_MONITOR_MAX_FRAME + 6U;
}
static inline int pc_monitor_frame_allowed(const unsigned char *frame, unsigned int bytes) {
    static const unsigned char bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
    static const unsigned char action[6] = {0x7f, 0, 0x17, 0xf2, 8, 0x10};
    if (!frame || bytes < 24 || bytes > PC_MONITOR_MAX_FRAME ||
        (frame[1] & 0xc7) || (frame[22] & 15)) return 0;
    for (unsigned int i = 0; i < 6; i++) if (frame[16+i] != bssid[i]) return 0;
    if (frame[0] == 0x08) return 1;
    if (frame[0] == 0x88) return bytes >= 26; /* A-MSDU remains supported. */
    if (frame[0] != 0xd0 || bytes < 40) return 0;
    for (unsigned int i = 0; i < 6; i++) if (frame[24+i] != action[i]) return 0;
    return 1;
}

#ifndef PC_MONITOR_PRIMARY_ALLOC
/* Measured immutable ROM ABI: 0x807c48 sets R2=0 and first calls 0x807b90.
 * Use that same first allocation path, without borrowing a shared RX-pool
 * buffer on failure. An optional monitor copy may instead be dropped.
 * The ROM page's hash is in monitor-profile-source.json. No arbitrary address input. */
#define PC_MONITOR_PRIMARY_ALLOC(osh, bytes) \
    (((struct sk_buff *(*)(void *, unsigned int, int))0x807b91UL)((osh), (bytes), 0))
#endif
#endif

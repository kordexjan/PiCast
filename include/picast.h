#ifndef PICAST_H
#define PICAST_H
#include <stddef.h>
#include <stdint.h>

/* Parsers allocate nothing. Callbacks borrow input only for their duration.
 * A malformed packet produces no callbacks: validate first, emit second. */
enum pc_result { PC_OK = 0, PC_OTHER = 1, PC_INVALID = -1, PC_UNSUPPORTED = -2 };
typedef void (*pc_item_fn)(uint8_t type, const uint8_t *value, size_t size, void *ctx);
struct pc_awdl {
    uint8_t source[6], version, subtype;
    uint32_t phy_time, target_time;
    size_t tags;
};
struct pc_ble {
    size_t apple_records, airplay_records, peer_records;
};
struct pc_awdl_sync {
    uint8_t tx_channel, master_channel, guard, master[6], presence;
    uint16_t tx_counter, aw_period_tu, action_period_tu, aw_counter;
};
struct pc_awdl_channels {
    uint16_t count, fill;
    uint8_t duplicate, step, number[256], operating_class[256];
};
struct pc_awdl_data {
    uint8_t source[6], destination[6];
    uint16_t sequence;
    const uint8_t *ipv6;
    size_t ipv6_size;
    uint8_t aggregate, long_header;
};
typedef void (*pc_data_fn)(const struct pc_awdl_data *data, void *ctx);
/* FCS-free 802.11 data, short/long AWDL headers and up to 64 A-MSDU
 * subframes. Validate the whole frame before any callback. Borrowed views;
 * callbacks must not modify input. No fragmentation, encryption or HT Control.
 * Conservative direct-link policy: inner DA/SA must equal outer DA/SA.
 * PC_OTHER: no AWDL IPv6 data; PC_OK: at least one IPv6 datagram. */
int pc_awdl_data_visit(const uint8_t *frame, size_t size, pc_data_fn callback, void *ctx);
/* Convenience view for exactly one datagram; multiple returns UNSUPPORTED.
 * Leaves out unchanged on every unsuccessful result. */
int pc_awdl_data_parse(const uint8_t *frame, size_t size, struct pc_awdl_data *out);
int pc_awdl_data_build(const uint8_t source[6], const uint8_t destination[6], uint16_t sequence,
                       const uint8_t *ipv6, size_t size, uint8_t *out, size_t capacity, size_t *written);
int pc_awdl_data_build_legacy(const uint8_t source[6], const uint8_t destination[6], uint16_t sequence,
                              const uint8_t *ipv6, size_t size, uint8_t *out, size_t capacity, size_t *written);
void pc_linklocal(const uint8_t mac[6], uint8_t address[16]);
/* ICMPv6 Echo with eight-byte nonce, no extension headers. */
int pc_echo_build(const uint8_t source[6], const uint8_t destination[6], uint16_t id,
                   uint16_t sequence, const uint8_t nonce[8], uint8_t out[56]);
int pc_echo_reply(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t id, uint16_t sequence, const uint8_t nonce[8]);
/* Reply to a checksum-valid Echo Request from the one owned peer. IPv6
 * extension headers/fragments are unsupported; never reflect other sources. */
int pc_echo_respond(const uint8_t *request, size_t size, const uint8_t own[6], const uint8_t peer[6],
                     uint8_t *out, size_t capacity, size_t *written);
/* Restricted RFC 4861 responder for our own link-local address and pinned peer.
 * No DAD, router advertisements, forwarding or proxy advertisements. */
int pc_neighbor_respond(const uint8_t *request, size_t size, const uint8_t own[6], const uint8_t peer[6],
                        uint8_t *out, size_t capacity, size_t *written);
int pc_neighbor_build(const uint8_t own[6], const uint8_t peer[6], uint8_t out[72]);
int pc_neighbor_reply(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6]);
/* Fixed DNS-SD service-enumeration query, legacy unicast response (RFC 6762). */
int pc_mdns_build(const uint8_t source[6], const uint8_t destination[6], uint16_t id, uint8_t out[94]);
int pc_mdns_group_build(const uint8_t source[6], uint8_t out[88]);
/* Diagnostic DNS-SD announcement with a token name, TTL 15 s (tests only). */
int pc_tcp_service_build(const uint8_t source[6], const uint8_t token[16], uint8_t out[421]);
/* The AirPlay DNS-SD announcement on the AWDL link (_airplay and _raop). */
int pc_airplay_service_build(const uint8_t source[6], const uint8_t token[16], const uint8_t public_key[32],
                             uint8_t *out, size_t capacity, size_t *written);
int pc_airplay_p2p_service_build(const uint8_t source[6], const uint8_t token[16], const uint8_t public_key[32],
                             uint8_t *out, size_t capacity, size_t *written);
int pc_service_build(const uint8_t source[6], const uint8_t token[16], uint8_t out[421]);
int pc_mdns_group_reply(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6], uint16_t *answers);
int pc_mdns_reply(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t id, uint16_t *answers);
/* Nonce-prefixed UDP echo probe for an explicitly registered owned service.
 * Fixed 36-byte payload: token[16], id/sequence BE16, "PiCast UDP probe".
 * This is a development diagnostic, not an AirPlay protocol message. */
int pc_udp_build(const uint8_t own[6], const uint8_t peer[6], uint16_t port, uint16_t id,
                  uint16_t sequence, const uint8_t token[16], uint8_t out[84]);
/* Restricted diagnostic echo: exact owned addresses, port, token and marker. */
int pc_udp_respond(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6],
                   uint16_t port, const uint8_t token[16], uint8_t out[84]);
int pc_udp_reply(const uint8_t *ipv6, size_t size, const uint8_t own[6], const uint8_t peer[6],
                  uint16_t port, uint16_t id, uint16_t sequence, const uint8_t token[16]);
int pc_print_awdl_data(const uint8_t *frame, size_t size);
/* One-hop follower: PiCast takes over a sender's AWDL timing, never becomes master. */
/* Schedule the follower announces. gaps leaves that many of every 8 slots (0..3) free
 * so the sender can serve its own WLAN; a slot lasts about 65 ms and the sender's video
 * stalls for that long (r190). solo sets the AirPlay Solo Mode bit. Default: 0, solo. */
void pc_awdl_follow_set_profile(int gaps, int solo);
/* Short text describing a peer frame's announced schedule; -1 if it has none. */
int pc_awdl_schedule_key(const uint8_t *frame, size_t size, char *out, size_t capacity);
int pc_awdl_follow_build(const uint8_t own[6], const uint8_t *peer_frame, size_t peer_size,
                         uint16_t sequence, uint32_t clock_us, uint8_t subtype, uint8_t *out, size_t capacity, size_t *written);
int pc_awdl_follow_build_at(const uint8_t own[6], const uint8_t *peer_frame, size_t peer_size,
                            uint32_t elapsed_us, uint16_t sequence, uint32_t clock_us, uint8_t subtype,
                            uint8_t *out, size_t capacity, size_t *written);
enum { PC_AWDL_MAX_AGE_US = 1572864, PC_AWDL_SNAPSHOT_MAX = 2048 };
struct pc_awdl_clock { uint16_t aw_counter; uint32_t remaining_us; };
/* Project the measured 16-TU/Presence-4 clock, including peer TX delay.
 * A host timestamp is only an estimate of RF time. Output unchanged on error. */
int pc_awdl_clock_project(const struct pc_awdl_sync *sync, uint32_t phy_time, uint32_t target_time,
                          uint32_t elapsed_us, struct pc_awdl_clock *out);
enum pc_peer_phase { PC_PEER_LISTENING, PC_PEER_ACQUIRING, PC_PEER_TRACKING, PC_PEER_EXPIRED };
enum pc_peer_events { PC_PEER_PSF = 1, PC_PEER_MIF = 2, PC_PEER_DATA = 4 };
struct pc_awdl_peer {
    uint8_t own[6], peer[6], master[6], consistent_samples;
    enum pc_peer_phase phase;
    uint64_t observed_us, psf_due_us, mif_due_us;
    uint32_t resyncs, holdover_reacquisitions, master_changes, clock_discontinuities, phy_time, target_time;
    uint16_t sequence;
    struct pc_awdl_sync sync;
    struct pc_awdl_channels channels;
    size_t frame_size;
    uint8_t frame[PC_AWDL_SNAPSHOT_MAX];
};
struct pc_awdl_plan {
    unsigned available;
    uint64_t next_wake_us;
    struct pc_awdl_clock clock;
    uint8_t channel, operating_class;
};
/* Follower for one selected sender, channel 6.
 * TRACKING means two consistent local clock observations, not peer admission.
 * Does not elect itself master, switch channels or perform I/O. Poll is a
 * preview; mark_sent advances deadlines only after a successful actual send. */
int pc_awdl_peer_init(struct pc_awdl_peer *state, const uint8_t own[6], const uint8_t peer[6]);
int pc_awdl_peer_observe(struct pc_awdl_peer *state, const uint8_t *frame, size_t size, uint64_t now_us);
int pc_awdl_peer_poll(struct pc_awdl_peer *state, uint64_t now_us, struct pc_awdl_plan *out);
int pc_awdl_peer_build(struct pc_awdl_peer *state, uint64_t now_us, unsigned event,
                       uint8_t *out, size_t capacity, size_t *written);
int pc_awdl_peer_mark_sent(struct pc_awdl_peer *state, uint64_t now_us, unsigned event);
/* Conservative channel-6 data gate, not a scheduler. Reject unknown windows,
 * stale snapshots and both EAW edges; elapsed includes planned send delay. */
int pc_awdl_data_window(const uint8_t *peer_frame, size_t peer_size, uint32_t elapsed_us);
enum pc_probe_options { PC_PROBE_FOLLOW = 1, PC_PROBE_MDNS = 2, PC_PROBE_OFDM = 4, PC_PROBE_UNICAST_FOLLOW = 8, PC_PROBE_LEGACY_DATA = 16, PC_PROBE_NEIGHBOR = 32, PC_PROBE_GROUP_REPLIES = 64, PC_PROBE_MDNS_GROUP = 128, PC_PROBE_PRIMARY_IDENTITY = 256, PC_PROBE_SERVICE = 512, PC_PROBE_TCP_SERVICE = 1024, PC_PROBE_RTSP_SERVICE = 2048, PC_PROBE_NATIVE_CONTROL = 4096, PC_PROBE_MEDIA_60S = 8192, PC_PROBE_MEDIA_10M = 16384,
    /* Product: a session may run up to 12 h; limits scale with its length. */
    PC_PROBE_MEDIA_HOLD = 32768 };
#define PC_PROBE_HOLD_SECONDS 43200U
/* What PiCast tells senders it is and can do: screen mirroring with audio,
 * FairPlay-protected setup, PIN pairing. The model tag selects the sender's
 * protocol variant; the receiver is still PiCast. */
#define PC_AIRPLAY_MODEL "AppleTV3,2"
#define PC_AIRPLAY_FEATURES ((UINT64_C(1)<<30)|(UINT64_C(1)<<27)|(UINT64_C(1)<<20)|(UINT64_C(1)<<19)|(UINT64_C(1)<<14)|(UINT64_C(1)<<7)|(UINT64_C(1)<<9))
#define PC_AIRPLAY_SOURCE_VERSION "220.68"
static inline uint64_t pc_airplay_features(void) { return (uint64_t)PC_AIRPLAY_FEATURES; }
int pc_udp_probe(const char *interface, const uint8_t peer[6], unsigned seconds, const char *path,
                  unsigned options, uint16_t port, const uint8_t token[16]);
/* Passive field decoding only; no clock synchronization or scheduling.
 * Sync fixed prefix is 33 bytes. Channel decoder supports encoding 3 only;
 * extension bytes remain available through the original raw TLV. */
int pc_awdl_sync_parse(const uint8_t *value, size_t size, struct pc_awdl_sync *out);
int pc_awdl_channels_parse(const uint8_t *value, size_t size, struct pc_awdl_channels *out);
/* Complete 802.11 management frame, FCS removed. Unknown TLVs preserved. */
int pc_awdl_parse(const uint8_t *frame, size_t size, struct pc_awdl *out,
                  pc_item_fn callback, void *ctx);
/* Complete BLE Advertising Data (AD structures), not a radio/HCI packet.
 * Callbacks carry Apple Continuity records; 0x16 remains uninterpreted. */
int pc_ble_parse(const uint8_t *ad, size_t size, struct pc_ble *out,
                 pc_item_fn callback, void *ctx);
/* Radiotap -> frame view. Only TSFT/Flags are interpreted to strip FCS and
 * reject bad-FCS frames. Other fields remain opaque. */
int pc_radiotap(const uint8_t *packet, size_t size,
                const uint8_t **frame, size_t *frame_size);
struct pc_radiotap_view {
    const uint8_t *frame;
    size_t frame_size;
    uint64_t tsft_us;
    uint8_t has_tsft, flags;
};
/* Firmware TSFT is available in existing Nexmon captures. Its capture point
 * is firmware processing, not a proven hardware RF arrival timestamp. */
int pc_radiotap_parse(const uint8_t *packet, size_t size, struct pc_radiotap_view *out);
struct pc_rx_clock { int64_t offset_us; uint64_t last_tsft; uint32_t samples, resets; };
/* Minimum observed host-minus-firmware offset estimates RX queue delay.
 * Does not establish an absolute hardware/host calibration. */
int pc_rx_clock_map(struct pc_rx_clock *clock, uint64_t tsft_us, uint64_t host_us, uint64_t *observed_us);
typedef void (*pc_report_fn)(const uint8_t *ad, size_t size, int rssi, void *ctx);
/* HCI event packet including packet-type byte; legacy LE advertising reports. */
int pc_ble_reports(const uint8_t *packet, size_t size, pc_report_fn fn, void *ctx);
int pc_print_awdl(const uint8_t *frame, size_t size);
/* Linux-only bounded diagnostics; other platforms return failure explicitly. */
int pc_capture(const char *interface, unsigned seconds);
int pc_capture_to_file(const char *interface, unsigned seconds, const char *path);
/* Classic PCAP, little endian, microsecond timestamps; no FCS inference. */
int pc_pcap_header(uint8_t out[24], uint32_t linktype);
int pc_pcap_record(uint8_t out[16], uint32_t seconds, uint32_t microseconds, size_t length);
struct pc_pcap_packet {
    const uint8_t *data;
    size_t size, original_size;
    uint32_t linktype;
    uint64_t timestamp_us;
};
typedef int (*pc_packet_fn)(const struct pc_pcap_packet *packet, void *ctx);
/* Streaming classic PCAP reader. Callback nonzero aborts; views are borrowed.
 * Supports both byte orders and timestamp resolutions. No live capture. */
int pc_pcap_walk(const char *path, pc_packet_fn callback, void *ctx);
/* Fixed radio queries for the device runner; see netlink.c. */
int pc_firmware_counters(const char *interface);
int pc_firmware_power(const char *interface);
int pc_firmware_monitor_awake(const char *interface);
/* Linux netlink attribute area (native endian, 4-byte alignment). */
int pc_netlink_attr(const uint8_t *data, size_t size, uint16_t type,
                    const uint8_t **value, size_t *value_size);
#endif

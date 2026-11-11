#ifndef PICAST_CONTROL_H
#define PICAST_CONTROL_H
#include "picast_pair.h"
#include "picast_rtsp.h"
#include "picast_pin.h"
#include "picast_fairplay.h"
enum pc_control_phase { PC_CONTROL_NEW, PC_CONTROL_PAIRED, PC_CONTROL_VERIFIED, PC_CONTROL_CLOSED };
struct pc_media;
struct pc_control {
    struct pc_media *media;
    uint8_t identity_seed[32], identity_public[32], device_id[6];
    struct pc_pair_verify pair;
    enum pc_control_phase phase;
    unsigned allow_transient;
    struct pc_pin pin;
    struct pc_fairplay fairplay;
    int (*show_pin)(const char code[5]);
    const char *state_dir;   /* where pairings outlive a session; NULL keeps none */
};
/* Fresh/cleared storage only; always call clear. Transient pairing is an
 * explicit per-session policy and provides no PIN or persistent client trust. */
int pc_control_init(struct pc_control *, const uint8_t seed[32], int allow_transient);
void pc_control_clear(struct pc_control *);
int pc_control_reconnect(struct pc_control *);
/* iOS remembers a pairing and only verifies on its next visit, so the receiver's
 * identity and the keys of paired senders must outlive the session process. */
int pc_pairing_identity(const char *dir, uint8_t seed[32]);
int pc_pairing_known(const char *dir, const uint8_t key[32]);
int pc_pairing_remember(const char *dir, const uint8_t key[32]);
/* Framed requests, including partial/pipelined input. Response capacity >=512
 * required before any state change. PC_OTHER leaves state/output untouched.
 * Caller must close transport on PC_CONTROL_CLOSED. Optional PC_NATIVE_MEDIA
 * requires actual isolated sockets and a verified session before SETUP. */
int pc_control_request(struct pc_control *, const uint8_t *, size_t,
                       uint8_t *response, size_t capacity, size_t *written, size_t *consumed);
#endif

#ifndef PICAST_INFO_H
#define PICAST_INFO_H
#include "picast.h"
/* Minimal /info metadata: legacy pairing only; no video/audio/display claims.
 * Standard OS/libplist serialization; no protocol state or key persistence. */
int pc_info_encode(const uint8_t device_id[6], const uint8_t public_key[32],
                    uint8_t *out, size_t capacity, size_t *written);
#endif

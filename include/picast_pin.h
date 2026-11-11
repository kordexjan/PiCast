#ifndef PICAST_PIN_H
#define PICAST_PIN_H
#include "picast_srp.h"
struct pc_pin {
    struct pc_srp srp;
    unsigned phase;
    char code[5];
    char retry_code[5];      /* survives a mistyped attempt, see pc_pin_request */
    unsigned wrong_attempts;
    uint8_t key[16], iv[16], peer_key[32];
};
/* Mistypes allowed for one displayed code: enough for people, useless for guessing. */
#define PC_PIN_MAX_ATTEMPTS 5U
int pc_pin_begin(struct pc_pin *p);
void pc_pin_clear(struct pc_pin *p);
/* Binary plist, exact typed fields, single-use proof and authenticated key
 * exchange. Returns 0 only after producing a real protocol response. */
int pc_pin_request(struct pc_pin *p, const uint8_t *input, size_t size,
                   const uint8_t own_key[32], uint8_t *out, size_t cap, size_t *written);
#endif

#ifndef PICAST_SESSION_H
#define PICAST_SESSION_H
#include <stddef.h>
#include <stdint.h>
/* Parsed encrypted offer, NOT decrypted/session-ready state. */
struct pc_session_offer {
    uint8_t wrapped_key[72], iv[16];
    uint16_t sender_timing_port;
    unsigned combined_info;
};
int pc_session_offer_parse(const uint8_t *, size_t, struct pc_session_offer *);
/* Prints the field names and the session kind of an offer, never values or keys. */
void pc_session_offer_describe(const uint8_t *input,size_t n);
#endif

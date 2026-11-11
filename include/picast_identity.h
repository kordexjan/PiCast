#ifndef PICAST_IDENTITY_H
#define PICAST_IDENTITY_H
#include <stdint.h>
/* Public discovery identifier, not an authentication credential. UUID with version-4 layout derived
 * from the freshly randomized public identity key; stable for that identity across TCP sessions. */
static inline void pc_airplay_pairing_id(const uint8_t public_key[16], char out[37]) {
    static const char hex[]="0123456789abcdef";
    unsigned n=0;
    for (unsigned i=0;i<16;i++) {
        if (i==4 || i==6 || i==8 || i==10) out[n++]='-';
        uint8_t byte=public_key[i];
        if (i==6) byte=(uint8_t)((byte & 15U) | 0x40U);
        if (i==8) byte=(uint8_t)((byte & 63U) | 0x80U);
        out[n++]=hex[byte>>4]; out[n++]=hex[byte&15U];
    }
    out[n]=0;
}
#endif

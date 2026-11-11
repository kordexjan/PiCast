#ifndef PICAST_FP_KEY_H
#define PICAST_FP_KEY_H
#include <stddef.h>
#include <stdint.h>
/* Sole boundary to the separately licensed PlayFair implementation.
 * Successful unwrap is NOT authentication of the encrypted media stream. */
int pc_fp_key_unwrap(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t out[16]);
#endif

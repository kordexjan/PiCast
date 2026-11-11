#ifndef PICAST_MIRROR_CRYPTO_H
#define PICAST_MIRROR_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
/* Cipher for type-0 mirror payloads only. Headers/codec configuration are
 * outside this continuous counter stream. No FairPlay key unwrap here. */
struct pc_mirror_cipher { void *context; uint64_t bytes; };
int pc_mirror_cipher_init(struct pc_mirror_cipher *, const uint8_t media_key[16],
                          const uint8_t ecdh_secret[32], uint64_t stream_id);
int pc_mirror_cipher_update(struct pc_mirror_cipher *, const uint8_t *input,
                            size_t size, uint8_t *out, size_t capacity);
void pc_mirror_cipher_clear(struct pc_mirror_cipher *);
#endif

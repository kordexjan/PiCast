#ifndef PICAST_PAIR_H
#define PICAST_PAIR_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
/* Legacy pair-verify only. Caller supplies the identity and an already
 * authorized client public key. This module does not establish PIN trust,
 * implement FairPlay, or claim encryption of subsequent RTSP traffic. */
enum pc_pair_phase { PC_PAIR_READY, PC_PAIR_WAITING, PC_PAIR_VERIFIED, PC_PAIR_FAILED };
struct pc_pair_verify {
    EVP_PKEY *identity;
    EVP_CIPHER_CTX *cipher;
    uint8_t trusted_client[32], client_x[32], server_x[32], shared_secret[32];
    enum pc_pair_phase phase;
};
int pc_identity_public(const uint8_t seed[32], uint8_t public_key[32]);
/* Initialize fresh storage, or storage previously released by pc_pair_clear.
 * Every successful initialization must be paired with pc_pair_clear. */
int pc_pair_init(struct pc_pair_verify *p, const uint8_t identity_seed[32], const uint8_t authorized_client[32]);
void pc_pair_clear(struct pc_pair_verify *p);
/* Exactly 68 request bytes -> 96 response bytes, then 68 proof bytes ->
 * verified/failed. Outputs unchanged on failure. A session is single-use. */
int pc_pair_begin(struct pc_pair_verify *p, const uint8_t *request, size_t n, uint8_t response[96]);
/* Copy only after mutual signature verification; output unchanged otherwise. */
int pc_pair_media_secret(const struct pc_pair_verify *, uint8_t out[32]);
int pc_pair_finish(struct pc_pair_verify *p, const uint8_t *request, size_t n);
#endif

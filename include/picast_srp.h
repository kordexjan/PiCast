#ifndef PICAST_SRP_H
#define PICAST_SRP_H
#include <stddef.h>
#include <stdint.h>
/* Legacy PIN pairing only. Fresh, single-use SRP-6a server; no persisted trust.
 * Initialize to zero. Failed proofs destroy all session secrets. */
struct pc_srp { void *private_state; unsigned phase; };
int pc_srp_start(struct pc_srp *s, const char *user, const char pin[5],
                 uint8_t salt[16], uint8_t public_b[256]);
int pc_srp_prove(struct pc_srp *s, const uint8_t public_a[256],
                 const uint8_t proof[20], uint8_t server_proof[20]);
int pc_srp_keys(struct pc_srp *s, uint8_t key[16], uint8_t iv[16]);
void pc_srp_clear(struct pc_srp *s);
#endif

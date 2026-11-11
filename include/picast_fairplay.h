#ifndef PICAST_FAIRPLAY_H
#define PICAST_FAIRPLAY_H
#include <stddef.h>
#include <stdint.h>
/* Version-3/modes-0..3 wire negotiation only. This state does NOT establish
 * sender authenticity or implement the wrapped media-key decoder. */
struct pc_fairplay { unsigned phase; uint8_t key_message[164]; };
int pc_fairplay_wire(struct pc_fairplay *, const uint8_t *input, size_t size,
                     uint8_t *out, size_t capacity, size_t *written);
void pc_fairplay_clear(struct pc_fairplay *);
#endif

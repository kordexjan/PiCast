#ifndef PICAST_MIRROR_H
#define PICAST_MIRROR_H
#include "picast.h"

#define PC_MIRROR_HEADER_SIZE 128U
#define PC_MIRROR_MAX_PAYLOAD (1024U * 1024U)
#define PC_H264_MAX_NALS 128U
struct pc_mirror_header { uint32_t payload_size; uint16_t type, flags; uint64_t ntp; uint16_t type_flags; };
struct pc_h264_config { unsigned length_bytes; };
/* Plaintext/decrypted payloads only. No allocation or authentication bypass.
 * Validate a complete packet before output; malformed data leaves out intact.
 * PC_OTHER means an incomplete header, not a malformed complete header.
 * Input, output and config storage must not overlap. */
int pc_mirror_header_parse(const uint8_t *input, size_t size, struct pc_mirror_header *header);
int pc_h264_config_decode(const uint8_t *input, size_t size, struct pc_h264_config *config,
                          uint8_t *out, size_t capacity, size_t *written);
int pc_h264_access_unit(const struct pc_h264_config *config, const uint8_t *input, size_t size,
                         uint8_t *out, size_t capacity, size_t *written);
#endif

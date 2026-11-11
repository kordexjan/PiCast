#ifndef PICAST_RTSP_H
#define PICAST_RTSP_H
#include "picast.h"
enum { PC_RTSP_HEADER_LIMIT = 8192, PC_RTSP_BODY_LIMIT = 65536, PC_RTSP_HEADERS = 64 };
struct pc_span { const uint8_t *data; size_t size; };
struct pc_rtsp_header { struct pc_span name, value; };
struct pc_rtsp_request {
    struct pc_span method, target, body;
    struct pc_rtsp_header headers[PC_RTSP_HEADERS];
    size_t header_count, consumed;
    uint32_t cseq;
    unsigned has_cseq, http;
};
/* Borrowed views, no allocation. PC_OTHER means more stream bytes required.
 * Output remains untouched on incomplete/invalid input. One request consumed;
 * trailing pipelined bytes belong to the next request. No chunked encoding. */
int pc_rtsp_parse(const uint8_t *p, size_t n, struct pc_rtsp_request *out);
int pc_rtsp_header(const struct pc_rtsp_request *r, const char *name, struct pc_span *out);
/* Caller-provided body must not overlap output. Only standard fixed status
 * reasons and a small whitelist of content types; no reflected header text. */
int pc_rtsp_response(const struct pc_rtsp_request *r, unsigned status, const char *type,
                     const uint8_t *body, size_t body_size, uint8_t *out, size_t capacity, size_t *written);
#endif

#ifndef _LIBGQUIC_PACKET_SHORT_HEADER_PACKET_H
#define _LIBGQUIC_PACKET_SHORT_HEADER_PACKET_H

#include "util/str.h"
#include <sys/types.h>

typedef struct gquic_packet_short_header_s gquic_packet_short_header_t;
struct gquic_packet_short_header_s {
    u_int8_t flag;
    u_int8_t dcid_len;
    u_int8_t dcid[20];
    u_int64_t pn;
};

gquic_packet_short_header_t *gquic_packet_short_header_alloc();
ssize_t gquic_packet_short_header_size(const gquic_packet_short_header_t *const header);
int gquic_packet_short_header_serialize(const gquic_packet_short_header_t *const header, gquic_writer_str_t *const writer);
int gquic_packet_short_header_deserialize(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader);


#endif

#ifndef _LIBGQUIC_PACKET_HEADER_H
#define _LIBGQUIC_PACKET_HEADER_H

#include "packet/long_header_packet.h"
#include "packet/short_header_packet.h"

typedef struct gquic_packet_header_s gquic_packet_header_t;
struct gquic_packet_header_s {
    int is_long;
    union {
        gquic_packet_long_header_t *l_hdr;
        gquic_packet_short_header_t *s_hdr;
    } hdr;
};

int gquic_packet_header_init(gquic_packet_header_t *const header);
u_int64_t gquic_packet_header_get_pn(gquic_packet_header_t *const header);
int gquic_packet_header_set_pn(gquic_packet_header_t *const header, const u_int64_t pn);
int gquic_packet_header_set_len(gquic_packet_header_t *const header, const u_int64_t len);
size_t gquic_packet_header_size(gquic_packet_header_t *const header);

#endif

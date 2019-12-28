#ifndef _LIBGQUIC_PACKET_PACKER_H
#define _LIBGQUIC_PACKET_PACKER_H

#include "packet/long_header_packet.h"
#include "packet/short_header_packet.h"

typedef struct gquic_packet_packer_s gquic_packet_packer_t;
struct gquic_packet_packer_s {
    int is_long;
    union {
        gquic_packet_long_header_t *long_header;
        gquic_packet_short_header_t *short_header;
    } header;
    size_t pn_len;
    u_int64_t pn;
};


#endif

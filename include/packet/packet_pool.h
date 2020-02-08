#ifndef _LIBGQUIC_PACKET_PACKET_POOL_H
#define _LIBGQUIC_PACKET_PACKET_POOL_H

#include "util/str.h"

typedef struct gquic_packet_buffer_s gquic_packet_buffer_t;
struct gquic_packet_buffer_s {
    gquic_str_t slice;
    int ref;
};

#endif

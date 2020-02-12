#ifndef _LIBGQUIC_PACKET_PACKET_POOL_H
#define _LIBGQUIC_PACKET_PACKET_POOL_H

#include "util/str.h"

typedef struct gquic_packet_buffer_s gquic_packet_buffer_t;
struct gquic_packet_buffer_s {
    gquic_str_t slice;
    gquic_writer_str_t writer;
    int ref;
};

int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage);
int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer_storage);

#endif

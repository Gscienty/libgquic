#ifndef _LIBGQUIC_PACKET_PACKET_POOL_H
#define _LIBGQUIC_PACKET_PACKET_POOL_H

#include "util/count_pointer.h"
#include "util/str.h"

typedef struct gquic_packet_buffer_s gquic_packet_buffer_t;
struct gquic_packet_buffer_s {
    gquic_str_t slice;
    gquic_writer_str_t writer;
};

typedef struct gquic_cptr_packet_buffer_s gquic_cptr_packet_buffer_t;
struct gquic_cptr_packet_buffer_s {
    gquic_packet_buffer_t buffer;
    gquic_count_pointer_t cptr;
};


int gquic_packet_buffer_get(gquic_packet_buffer_t **const buffer_storage);
int gquic_packet_buffer_put(gquic_packet_buffer_t *const buffer);
int gquic_packet_buffer_assign(gquic_packet_buffer_t **const buffer_storage, gquic_packet_buffer_t *const buffer);

#endif

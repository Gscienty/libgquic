#ifndef _LIBGQUIC_PACKET_PACKET_H
#define _LIBGQUIC_PACKET_PACKET_H

#include "util/list.h"
#include "util/count_pointer.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>

typedef struct gquic_packet_s gquic_packet_t;
struct gquic_packet_s {
    u_int64_t pn;
    GQUIC_CPTR_TYPE(gquic_list_t) frames; /* void ** */
    u_int64_t largest_ack;
    u_int64_t len;
    u_int8_t enc_lv;
    u_int64_t send_time;
    bool included_infly;
};

gquic_exception_t gquic_packet_init(gquic_packet_t *const packet);
gquic_exception_t gquic_packet_dtor(gquic_packet_t *const packet);

typedef struct gquic_cptr_frames_s gquic_cptr_frames_t;
struct gquic_cptr_frames_s {
    gquic_list_t frames;
    gquic_count_pointer_t cptr;
};

gquic_exception_t gquic_cptr_frames_dtor(void *const frames);

typedef struct gquic_cptr_packet_s gquic_cptr_packet_t;
struct gquic_cptr_packet_s {
    gquic_packet_t packet;
    gquic_count_pointer_t cptr;
};

gquic_exception_t gquic_cptr_packet_dtor(void *const packet);

#endif

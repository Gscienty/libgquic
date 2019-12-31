#ifndef _LIBGQUIC_PACKET_PACKET_H
#define _LIBGQUIC_PACKET_PACKET_H

#include <sys/types.h>
#include "util/list.h"

typedef struct gquic_packet_s gquic_packet_t;
struct gquic_packet_s {
    u_int64_t pn;
    gquic_list_t frames; /* void ** */
    u_int64_t largest_ack;
    u_int64_t len;
    u_int8_t enc_lv;
    u_int64_t send_time;
    int included_infly;
};

int gquic_packet_init(gquic_packet_t *const packet);
int gquic_packet_dtor(gquic_packet_t *const packet);

#endif

#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include <sys/types.h>
#include "util/list.h"

size_t gquic_packet_number_size(const u_int64_t pn);
unsigned char gquic_packet_number_flag(const u_int64_t pn);
size_t gquic_packet_number_flag_to_size(const u_int8_t flag);

typedef struct gquic_packet_number_gen_s gquic_packet_number_gen_t;
struct gquic_packet_number_gen_s {
    u_int64_t average;
    u_int64_t next;
    u_int64_t skip;
    gquic_list_t mem;
};

int gquic_packet_number_gen_init(gquic_packet_number_gen_t *const gen);
int gquic_packet_number_gen_dtor(gquic_packet_number_gen_t *const gen);

#endif

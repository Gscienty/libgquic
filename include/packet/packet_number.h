#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include <sys/types.h>
#include "util/list.h"
#include "frame/ack.h"

size_t gquic_packet_number_size(const u_int64_t pn);
unsigned char gquic_packet_number_flag(const u_int64_t pn);
size_t gquic_packet_number_flag_to_size(const u_int8_t flag);

typedef struct gquic_packet_number_gen_s gquic_packet_number_gen_t;
struct gquic_packet_number_gen_s {
    u_int64_t average;
    u_int64_t next;
    u_int64_t skip;
    int mem_count;
    gquic_list_t mem;
};

int gquic_packet_number_gen_init(gquic_packet_number_gen_t *const gen);
int gquic_packet_number_gen_ctor(gquic_packet_number_gen_t *const gen, const u_int64_t init_pn, const u_int64_t average);
int gquic_packet_number_gen_dtor(gquic_packet_number_gen_t *const gen);
int gquic_packet_number_gen_new_skip(gquic_packet_number_gen_t *const gen);
int gquic_packet_number_gen_next(u_int64_t *const pn, gquic_packet_number_gen_t *const gen);
int gquic_packet_number_gen_valid(gquic_packet_number_gen_t *const gen, const gquic_list_t *const blocks);

static inline int gquic_packet_number_len(const u_int64_t pn, const u_int64_t lowest_unacked) {
    const u_int64_t diff = pn - lowest_unacked;
    if (diff < (1 << 15)) {
        return 2;
    }
    if (diff < (1 << 23)) {
        return 3;
    }
    return 4;
}

#define GQUIC_PACKET_NUMBER_DELTA(a, b) (((a) > (b)) ? ((a) - (b)) : ((b) - (a)))

static inline u_int64_t gquic_packet_number_close_to(const u_int64_t target, const u_int64_t a, const u_int64_t b) {
    return GQUIC_PACKET_NUMBER_DELTA(target, a) < GQUIC_PACKET_NUMBER_DELTA(target, b) ? a : b;
}

static inline u_int64_t gquic_packet_number_decode(const int pn_len, const u_int64_t last_pn, const u_int64_t pn) {
    u_int64_t epoch_delta = 0;
    u_int64_t epoch = 0;
    u_int64_t prev_epoch_begin = 0;
    u_int64_t next_epoch_begin = 0;
    switch (pn_len) {
    case 1:
        epoch_delta = 1UL << 8;
        break;
    case 2:
        epoch_delta = 1UL << 16;
        break;
    case 3:
        epoch_delta = 1UL << 24;
        break;
    case 4:
        epoch_delta = 1UL << 32;
        break;
    }
    epoch = last_pn & ~(epoch_delta - 1);
    if (epoch > epoch_delta) {
        prev_epoch_begin = epoch - epoch_delta;
    }
    next_epoch_begin = epoch + epoch_delta;
    return gquic_packet_number_close_to(last_pn + 1, epoch + pn,
                                        gquic_packet_number_close_to(last_pn + 1, prev_epoch_begin + pn, next_epoch_begin + pn));
}

#endif

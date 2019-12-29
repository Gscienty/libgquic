#ifndef _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/packet_number.h"
#include "util/list.h"
#include "util/rbtree.h"

typedef struct gquic_packet_sent_mem_s gquic_packet_sent_mem_t;
struct gquic_packet_sent_mem_s {
    int count;
    gquic_list_t list;
    gquic_rbtree_t *root;
};

int gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem);
int gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem);
int gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const gquic_packet_t *const packet);
int gquic_packet_sent_mem_get_packet(const gquic_packet_t **const packet, gquic_packet_sent_mem_t *const mem, const u_int64_t pn);
int gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn, int (*release_packet_func) (gquic_packet_t *const));

typedef struct gquic_packet_sent_pn_s gquic_packet_sent_pn_t;
struct gquic_packet_sent_pn_s {
    gquic_packet_sent_mem_t mem;
    gquic_packet_number_gen_t pn_gen;

    u_int64_t loss_time;
    u_int64_t last_sent_ack;

    u_int64_t largest_ack;
    u_int64_t largest_sent;
};

int gquic_packet_sent_pn_init(gquic_packet_sent_pn_t *const sent_pn);

#endif

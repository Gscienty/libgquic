#ifndef _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H

#include "packet/packet.h"
#include "util/list.h"
#include "util/rbtree.h"

typedef struct gquic_packet_sent_mem_s gquic_packet_sent_mem_t;
struct gquic_packet_sent_mem_s {
    gquic_list_t list;
    gquic_rbtree_t *root;
};

int gquic_packet_sent_mem_init(gquic_packet_sent_mem_t *const mem);
int gquic_packet_sent_mem_dtor(gquic_packet_sent_mem_t *const mem);
int gquic_packet_sent_mem_sent_packet(gquic_packet_sent_mem_t *const mem, const gquic_packet_t *const packet);
int gquic_packet_sent_mem_get_packet(const gquic_packet_t **const packet, gquic_packet_sent_mem_t *const mem, const u_int64_t pn);
int gquic_packet_sent_mem_remove(gquic_packet_sent_mem_t *const mem, const u_int64_t pn, int (*release_packet_func) (gquic_packet_t *const));

typedef struct gquic_packet_sent_handler_s gquic_packet_sent_handler_t;
struct gquic_packet_sent_handler_s {
    gquic_packet_sent_mem_t mem;
};

#endif

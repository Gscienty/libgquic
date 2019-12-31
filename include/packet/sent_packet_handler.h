#ifndef _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_SENT_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/packet_number.h"
#include "util/list.h"
#include "util/rbtree.h"
#include "cong/cubic.h"
#include "event/event.h"
#include "frame/ack.h"

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
    u_int64_t last_sent_ack_time;

    u_int64_t largest_ack;
    u_int64_t largest_sent;
};

int gquic_packet_sent_pn_init(gquic_packet_sent_pn_t *const sent_pn);
int gquic_packet_sent_pn_ctor(gquic_packet_sent_pn_t *const sent_pn, const u_int64_t init_pn);
int gquic_packet_sent_pn_dtor(gquic_packet_sent_pn_t *const sent_pn);

typedef struct gquic_packet_sent_packet_handler_s gquic_packet_sent_packet_handler_t;
struct gquic_packet_sent_packet_handler_s {
    u_int64_t next_send_time;
    gquic_packet_sent_pn_t *initial_packets;
    gquic_packet_sent_pn_t *handshake_packets;
    gquic_packet_sent_pn_t *one_rtt_packets;
    int handshake_complete;
    u_int64_t lowest_not_confirm_acked;
    u_int64_t infly_bytes;
    gquic_cong_cubic_t cong;
    const gquic_rtt_t *rtt;
    u_int32_t pto_count;
    u_int8_t pto_mode;
    int num_probes_to_send;
    u_int64_t alarm;
    struct {
        void *self;
        int (*cb)(void *const, gquic_event_t *const);
    } event_cb;
};

int gquic_packet_sent_packet_handler_init(gquic_packet_sent_packet_handler_t *const handler);
int gquic_packet_sent_packet_handler_ctor(gquic_packet_sent_packet_handler_t *const handler,
                                          const u_int64_t initial_pn,
                                          const gquic_rtt_t *const rtt,
                                          void *const event_self,
                                          int (*event_cb)(void *const, gquic_event_t *const));
int gquic_packet_sent_packet_handler_dtor(gquic_packet_sent_packet_handler_t *const handler);
int gquic_packet_sent_packet_handler_drop_packets(gquic_packet_sent_packet_handler_t *const handler,
                                                  const u_int8_t enc_lv);
int gquic_packet_sent_packet_sent_packet(gquic_packet_sent_packet_handler_t *const handler,
                                         gquic_packet_t *const packet);
int gquic_packet_sent_packet_received_ack(gquic_packet_sent_packet_handler_t *const handler,
                                          const gquic_frame_ack_t *const ack_frame,
                                          const u_int64_t wpn,
                                          const u_int8_t enc_lv,
                                          const u_int64_t recv_time);

#endif

#ifndef _LIBGQUIC_PACKET_RETRANSMISSION_QUEUE_H
#define _LIBGQUIC_PACKET_RETRANSMISSION_QUEUE_H

#include "util/list.h"
#include <sys/types.h>

typedef struct gquic_retransmission_queue_s gquic_retransmission_queue_t;
struct gquic_retransmission_queue_s {
    gquic_list_t initial;
    gquic_list_t initial_crypto;
    gquic_list_t handshake;
    gquic_list_t handshake_crypto;
    gquic_list_t app;
};

int gquic_retransmission_queue_init(gquic_retransmission_queue_t *const queue);
int gquic_retransmission_queue_add_initial(gquic_retransmission_queue_t *const queue, void *const frame);
int gquic_retransmission_queue_add_handshake(gquic_retransmission_queue_t *const queue, void *const frame);
int gquic_retransmission_queue_add_app(gquic_retransmission_queue_t *const queue, void *const frame);
int gquic_retransmission_queue_has_initial(gquic_retransmission_queue_t *const queue);
int gquic_retransmission_queue_has_handshake(gquic_retransmission_queue_t *const queue);
int gquic_retransmission_queue_get_initial(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);
int gquic_retransmission_queue_get_handshake(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);
int gquic_retransmission_queue_get_app(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);
int gquic_retransmission_queue_drop_packets(gquic_retransmission_queue_t *const queue, const u_int8_t enc_lv);

#endif

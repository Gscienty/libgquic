#ifndef _LIBGQUIC_PACKET_SEND_QUEUE_H
#define _LIBGQUIC_PACKET_SEND_QUEUE_H

#include "net/conn.h"
#include "packet/packer.h"
#include "liteco.h"

#define GQUIC_PACKET_SEND_QUEUE_EVENT_CLOSE 0x01
#define GQUIC_PACKET_SEND_QUEUE_EVENT_PACKET 0x02

typedef struct gquic_packet_send_queue_event_s gquic_packet_send_queue_event_t;
struct gquic_packet_send_queue_event_s {
    u_int8_t event;
    gquic_packed_packet_t *packed_packet;
};

typedef struct gquic_packet_send_queue_s gquic_packet_send_queue_t;
struct gquic_packet_send_queue_s {
    liteco_channel_t queue_chain;
    gquic_net_conn_t *conn;
};

int gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue);
int gquic_packet_send_queue_ctor(gquic_packet_send_queue_t *const queue, gquic_net_conn_t *const conn);
int gquic_packet_send_queue_dtor(gquic_packet_send_queue_t *const queue);
int gquic_packet_send_queue_send(gquic_packet_send_queue_t *const queue, gquic_packed_packet_t *const packed_packet);
int gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue);
int gquic_packet_send_queue_run(gquic_packet_send_queue_t *const queue);

#endif

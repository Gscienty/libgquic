#ifndef _LIBGQUIC_PACKET_RECEIVED_PACKET_H
#define _LIBGQUIC_PACKET_RECEIVED_PACKET_H

#include "packet/header.h"
#include "net/addr.h"
#include "util/str.h"
#include "packet/packet_pool.h"
#include <sys/types.h>

typedef struct gquic_received_packet_s gquic_received_packet_t;
struct gquic_received_packet_s {
    gquic_net_addr_t remote_addr;
    u_int64_t recv_time;
    gquic_str_t data;
    gquic_str_t dst_conn_id;

    gquic_packet_buffer_t *buffer;
};

int gquic_received_packet_init(gquic_received_packet_t *const recv_packet);
gquic_received_packet_t *gquic_received_packet_copy(gquic_received_packet_t *const recv_packet);


#endif

#include "packet/received_packet.h"
#include <malloc.h>

int gquic_received_packet_init(gquic_received_packet_t *const recv_packet) {
    if (recv_packet == NULL) {
        return -1;
    }
    gquic_net_addr_init(&recv_packet->remote_addr);
    recv_packet->recv_time = 0;
    gquic_str_init(&recv_packet->data);
    recv_packet->buffer = NULL;
    gquic_str_init(&recv_packet->dst_conn_id);

    return 0;
}

gquic_received_packet_t *gquic_received_packet_copy(gquic_received_packet_t *const recv_packet) {
    gquic_received_packet_t *ret = NULL;
    if (recv_packet == NULL) {
        return NULL;
    }
    if ((ret = malloc(sizeof(gquic_received_packet_t))) == NULL) {
        return NULL;
    }
    *ret = *recv_packet;

    return 0;
}

#include "packet/received_packet.h"

int gquic_received_packet_init(gquic_received_packet_t *const recv_packet) {
    if (recv_packet == NULL) {
        return -1;
    }
    gquic_net_addr_init(&recv_packet->remote_addr);
    recv_packet->recv_time = 0;
    gquic_str_init(&recv_packet->data);
    recv_packet->buffer = NULL;
    gquic_packet_header_init(&recv_packet->header);

    return 0;
}

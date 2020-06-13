#include "packet/received_packet.h"
#include "util/malloc.h"
#include "exception.h"

int gquic_received_packet_init(gquic_received_packet_t *const recv_packet) {
    if (recv_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_net_addr_init(&recv_packet->remote_addr);
    recv_packet->recv_time = 0;
    gquic_str_init(&recv_packet->data);
    recv_packet->buffer = NULL;
    gquic_str_init(&recv_packet->dst_conn_id);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_received_packet_copy(gquic_received_packet_t **const target, gquic_received_packet_t *const recv_packet) {
    if (target == NULL || recv_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(target, gquic_received_packet_t));
    **target = *recv_packet;
    gquic_packet_buffer_assign(&(*target)->buffer, recv_packet->buffer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

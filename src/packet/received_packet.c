/* src/packet/received_packet.c 接收到的数据包
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/received_packet.h"
#include "util/malloc.h"
#include "exception.h"

gquic_exception_t gquic_received_packet_init(gquic_received_packet_t *const recv_packet) {
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

/* include/packet/received_packet.h 接收到的数据包
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_RECEIVED_PACKET_H
#define _LIBGQUIC_PACKET_RECEIVED_PACKET_H

#include "packet/header.h"
#include "net/addr.h"
#include "util/str.h"
#include "packet/packet_pool.h"
#include "exception.h"
#include <sys/types.h>

/**
 * 接收到的数据包实体
 */
typedef struct gquic_received_packet_s gquic_received_packet_t;
struct gquic_received_packet_s {

    // 源地址
    gquic_net_addr_t remote_addr;

    // 接收时间
    u_int64_t recv_time;

    // 接收到的原始数据
    gquic_str_t data;

    // 数据包指定的目标connection id
    gquic_str_t dst_conn_id;

    // 数据包内存块
    gquic_packet_buffer_t *buffer;
};

/**
 * 初始化接收到的数据包实体
 *
 * @param recv_packet: 数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_received_packet_init(gquic_received_packet_t *const recv_packet);

#endif

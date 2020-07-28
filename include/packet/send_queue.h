/* include/packet/send_queue.h 数据包发送队列
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_SEND_QUEUE_H
#define _LIBGQUIC_PACKET_SEND_QUEUE_H

#include "net/conn.h"
#include "packet/packer.h"
#include "liteco.h"

/**
 * 数据包发送队列
 */
typedef struct gquic_packet_send_queue_s gquic_packet_send_queue_t;
struct gquic_packet_send_queue_s {

    // 数据包发送队列
    liteco_channel_t queue_chan;

    // UDP发送模块
    gquic_net_conn_t *conn;
};

/**
 * 初始化数据包发送队列
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_init(gquic_packet_send_queue_t *const queue);

/**
 * 构造数据包发送队列
 *
 * @param queue: queue
 * @param conn: UDP发送模块
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_ctor(gquic_packet_send_queue_t *const queue, gquic_net_conn_t *const conn);

/**
 * 析构数据包发送队列
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_dtor(gquic_packet_send_queue_t *const queue);

/**
 * 向数据包发送队列中添加一个要发送的数据包
 *
 * @param queue: queue
 * @param packed_packet: 数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_send(gquic_packet_send_queue_t *const queue, gquic_packed_packet_t *const packed_packet);

/**
 * 关闭数据包发送队列
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_close(gquic_packet_send_queue_t *const queue);

/**
 * 执行数据包发送队列监听运行（协程中）
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_send_queue_run(gquic_packet_send_queue_t *const queue);

#endif

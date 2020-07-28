/* include/packet/retransmission_queue.h 超时重发队列
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_RETRANSMISSION_QUEUE_H
#define _LIBGQUIC_PACKET_RETRANSMISSION_QUEUE_H

#include "util/list.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>

/**
 * 超时重发队列
 */
typedef struct gquic_retransmission_queue_s gquic_retransmission_queue_t;
struct gquic_retransmission_queue_s {

    // 加密级别为initial时需重发的数据帧
    gquic_list_t initial;

    // 加密级别为initial时需重发的TLS握手数据帧
    gquic_list_t initial_crypto;

    // 加密级别为handshake时需重发的数据帧
    gquic_list_t handshake;

    // 加密级别为handshake时需重发的TLS握手数据帧
    gquic_list_t handshake_crypto;

    // 加密级别为1rtt时需要重发的数据帧
    gquic_list_t app;
};

/**
 * 超时重发队列初始化
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_retransmission_queue_init(gquic_retransmission_queue_t *const queue);

/**
 * 根据特定的加密级别向超时重发队列中添加数据帧
 *
 * @param queue: queue
 * @param frame: frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_retransmission_queue_add_initial(gquic_retransmission_queue_t *const queue, void *const frame);
gquic_exception_t gquic_retransmission_queue_add_handshake(gquic_retransmission_queue_t *const queue, void *const frame);
gquic_exception_t gquic_retransmission_queue_add_app(gquic_retransmission_queue_t *const queue, void *const frame);

/**
 * 指定加密级别的超时重发队列中是否还有数据帧
 *
 * @param queue: queue
 * 
 * @return: 是否包含数据帧
 */
static inline bool gquic_retransmission_queue_has_initial(gquic_retransmission_queue_t *const queue) {
    if (queue == NULL) {
        return false;
    }
    return !gquic_list_head_empty(&queue->initial) || !gquic_list_head_empty(&queue->initial_crypto);
}

static inline bool gquic_retransmission_queue_has_handshake(gquic_retransmission_queue_t *const queue) {
    if (queue == NULL) {
        return 0;
    }
    return !gquic_list_head_empty(&queue->handshake) || !gquic_list_head_empty(&queue->handshake_crypto);
}


/**
 * 从指定的加密级别的重发队列中获取一个数据帧
 *
 * @param queue: queue
 * @param size: 数据包剩余长度
 *
 * @return frame: frame
 * @return: exception
 */
gquic_exception_t gquic_retransmission_queue_get_initial(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);
gquic_exception_t gquic_retransmission_queue_get_handshake(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);
gquic_exception_t gquic_retransmission_queue_get_app(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size);

/**
 * 清空指定的加密级别的重发队列中的数据帧
 *
 * @param queue: queue
 * @param enc_lv: 加密级别
 *
 * @return: exception
 */
gquic_exception_t gquic_retransmission_queue_drop_packets(gquic_retransmission_queue_t *const queue, const u_int8_t enc_lv);

#endif

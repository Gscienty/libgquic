/* include/packet/handler.h packet handler抽象类
 * 覆盖正常的packet handler/closed_handler
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_HANDLER_H
#define _LIBGQUIC_PACKET_HANDLER_H

#include "packet/packet.h"
#include "packet/received_packet.h"
#include "util/io.h"
#include <stdbool.h>

/**
 * packet handler抽象类
 */
typedef struct gquic_packet_handler_s gquic_packet_handler_t;
struct gquic_packet_handler_s {

    // 处理接收到的packet
    struct {
        void *self;
        int (*cb) (void *const, gquic_received_packet_t *const);
    } handle_packet;

    // 主动关闭处理过程的封装
    gquic_io_t closer;

    // 销毁
    struct {
        void *self;
        int (*cb) (void *const, const int);
    } destroy;

    // 是否为客户端
    bool is_client;
};

/**
 * 处理接收到的packet
 *
 * @param handler: packet handler
 * @param packet: 接收的packet
 *
 * @return: exception
 */
#define GQUIC_PACKET_HANDLER_HANDLE_PACKET(handler, packet) \
    (((gquic_packet_handler_t *) (handler))->handle_packet.cb(((gquic_packet_handler_t *) (handler))->handle_packet.self, (packet)))

/**
 * 销毁
 * @param handler: packet handler
 * @param err: 错误代码
 *
 * @return: exception
 */
#define GQUIC_PACKET_HANDLER_DESTROY(handler, err) \
    (((gquic_packet_handler_t *) (handler))->destroy.cb(((gquic_packet_handler_t *) (handler))->destroy.self, err))

/**
 * 是否为客户端
 *
 * @param handler: packet handler
 * 
 * @return 是否为客户端
 */
#define GQUIC_PACKET_HANDLER_IS_CLIENT(handler) (((gquic_packet_handler_t *) (handler))->is_client)

/**
 * packet handler初始化
 *
 * @param handler: packet handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_init(gquic_packet_handler_t *const handler);

#endif

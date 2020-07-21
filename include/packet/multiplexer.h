/* include/packet/multiplexer.h UDP到QUIC的复用模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_MULTIPLEXER_H
#define _LIBGQUIC_PACKET_MULTIPLEXER_H

#include "util/str.h"
#include "packet/packet_handler_map.h"

/**
 * 添加一个UDP到QUIC的映射
 *
 * @param conn_fd: UDP文件描述
 * @param conn_id_len: connection id长度
 * @param stateless_reset_token: token
 * 
 * @return handler_storage: packet handler
 * @return: exception
 */
gquic_exception_t gquic_multiplexer_add_conn(gquic_packet_handler_map_t **const handler_storage,
                                             const int conn_fd, const int conn_id_len, const gquic_str_t *const stateless_reset_token);

/**
 * 从映射关系列表中删除一个UDP到QUIC的映射
 *
 * @param: conn_fd: UDP文件描述
 *
 * @return: exception
 */
gquic_exception_t gquic_multiplexer_remove_conn(const gquic_exception_t conn_fd);

#endif

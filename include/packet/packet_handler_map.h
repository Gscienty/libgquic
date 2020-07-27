/* include/packet/packet_handler_map.h 用于UDP到QUIC的数据包分发
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_HANDLER_MAP_H
#define _LIBGQUIC_PACKET_HANDLER_MAP_H

#include "util/rbtree.h"
#include "packet/received_packet.h"
#include "packet/handler.h"
#include "liteco.h"
#include <stdbool.h>
#include <pthread.h>
#include <openssl/hmac.h>

/**
 * 用于服务端处理未知connection id的数据包处理模块
 */
typedef struct gquic_packet_unknow_packet_handler_s gquic_packet_unknow_packet_handler_t;
struct gquic_packet_unknow_packet_handler_s {

    // 处理接收的数据包
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, gquic_received_packet_t *const);
    } handle_packet;

    // 关闭该处理模块
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const int);
    } set_close_err;
};

/**
 * 初始化未知connection id数据包处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_unknow_packet_handler_init(gquic_packet_unknow_packet_handler_t *const handler);

/**
 * 处理新connection id的数据包
 *
 * @param handler: handler
 * @param packet: 数据包
 *
 * @return: exception
 */
#define GQUIC_PACKET_UNKNOW_PACKET_HANDLER_HANDLE_PACKET(handler, packet) \
    ((handler)->handle_packet.cb((handler)->handle_packet.self, (packet)))

/**
 * 关闭处理新connection id的数据包模块
 *
 * @param handler: handler
 * @param err: 错误代码
 *
 * @return: exception
 */
#define GQUIC_PACKET_UNKNOW_PACKET_HANDLER_SET_CLOSE_ERR(handler, err) \
    ((handler)->set_close_err.cb((handler)->set_close_err.self, (err)))

/**
 * 接收数据包分发模块
 */
typedef struct gquic_packet_handler_map_s gquic_packet_handler_map_t;
struct gquic_packet_handler_map_s {
    pthread_mutex_t mtx;

    // UDP fd
    int conn_fd;

    // connection id 长度
    int conn_id_len;

    // <connection id, packet_handler> 映射关系
    gquic_rbtree_t *handlers; /* gquic_str_t: gquic_packet_handler_t * */
    // <token, packet_handler> 映射关系
    gquic_rbtree_t *reset_tokens; /* gquic_str_t: gquic_packet_handler_t * */

    // 处理新connection id连接请求的模块
    gquic_packet_unknow_packet_handler_t *server;

    // 当前模块是否处于监听状态
    liteco_channel_t listen_chan;
    // 当前模块是否已经关闭
    bool closed;

    // 接收IO事件消息通道
    liteco_channel_t recv_event_chan;
    // 接收关闭事件的消息通道
    liteco_channel_t close_chan;

    // 关闭超时时间
    u_int64_t delete_retired_session_after;

    // 是否开启连接重置
    bool stateless_reset_enabled;

    // 连接重置key
    gquic_str_t stateless_reset_key;

};

/**
 * 初始化接收数据包分发模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_init(gquic_packet_handler_map_t *const handler);

/**
 * 构造接收数据包分发模块
 *
 * @param handler: handler
 * @param conn_fd: UDP连接fd
 * @param conn_id_len: connection id长度
 * @param stateless_reset_token: 连接重置token
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_ctor(gquic_packet_handler_map_t *const handler,
                                                const int conn_fd, const int conn_id_len, const gquic_str_t *const stateless_reset_token);

/**
 * 析构接收数据包分发模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_dtor(gquic_packet_handler_map_t *const handler);

/**
 * 向数据包分发模块添加一个connection id -> 数据包处理模块的映射关系
 *
 * @param handler: handler
 * @param conn_id: connection id
 * @param ph: 数据包处理模块
 *
 * @return token: 连接重置token
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_add(gquic_str_t *const token,
                                               gquic_packet_handler_map_t *const handler,
                                               const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph);

/**
 * 处理一个接收到的数据包
 *
 * @param handler: handler
 * @param rp: 接收的数据包
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_handle_packet(gquic_packet_handler_map_t *const handle_map, gquic_received_packet_t *const rp);

/**
 * 不获取连接重置token情况下，添加一个connection id -> 数据包处理模块的映射关系
 *
 * @param handler: handler
 * @param conn_id: connection id
 * @param ph: 数据包处理模块
 *
 * @return: 是否添加
 */
bool gquic_packet_handler_map_add_if_not_taken(gquic_packet_handler_map_t *handler,
                                               const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph);

/**
 * 移除一个映射关系
 *
 * @param handler: handler
 * @param conn_id: connection id
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_remove(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id);

/**
 * 使一个映射关系失效
 *
 * @param handler: handler
 * @param conn_id: connection id
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_retire(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id);

/**
 * 将一个映射关系中的数据包处理模块置换，并关闭该映射关系
 *
 * @param handler: handler
 * @param conn_id: connection id
 * @param ph: 新的数据包处理模块
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_replace_with_closed(gquic_packet_handler_map_t *const handler,
                                                               const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph);

/**
 * 添加一个token -> 数据包处理模块的映射关系
 *
 * @param handler: handler
 * @param token: token
 * @param ph: 新的数据包处理模块
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_add_reset_token(gquic_packet_handler_map_t *const handler,
                                                           const gquic_str_t *const token, gquic_packet_handler_t *const ph);
/**
 * 移除一个映射关系
 *
 * @param handler: handler
 * @param token: token
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_remove_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token);

/**
 * 使一个映射关系失效
 *
 * @param handler: handler
 * @param token: token
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_retire_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token);

/**
 * 设置一个接收新connection id的数据包处理模块
 *
 * @param handler: handler
 * @param uph: 数据包处理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_set_server(gquic_packet_handler_map_t *const handler, gquic_packet_unknow_packet_handler_t *const uph);

/**
 * 关闭接收新connection id的数据包处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_close_server(gquic_packet_handler_map_t *const handler);

/**
 * 关闭数据包处理模块
 *
 * @param handler: handler
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_close(gquic_packet_handler_map_t *const handler);

/**
 * 根据connection id获取重置连接的token
 *
 * @param handler: handler
 * @param conn_id: connection id
 * 
 * @return token: token
 * @return: exception
 */
gquic_exception_t gquic_packet_handler_map_get_stateless_reset_token(gquic_str_t *const token,
                                                                     gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id);

#endif

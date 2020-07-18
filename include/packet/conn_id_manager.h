/* include/packet/conn_id_manager.h connection id 管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_CONN_ID_MANAGER_H
#define _LIBGQUIC_PACKET_CONN_ID_MANAGER_H

#include "util/list.h"
#include "util/str.h"
#include "frame/new_connection_id.h"
#include "exception.h"
#include <sys/types.h>

/**
 * 新connection id
 */
typedef struct gquic_new_conn_id_s gquic_new_conn_id_t;
struct gquic_new_conn_id_s {

    // 序号
    u_int64_t seq;

    // connection id
    gquic_str_t conn_id;

    // token
    u_int8_t token[16];
};

/**
 * connection id管理模块
 */
typedef struct gquic_conn_id_manager_s gquic_conn_id_manager_t;
struct gquic_conn_id_manager_s {

    // 存储的connection id个数
    int queue_len;
    // 存储connection id
    gquic_list_t queue; /* gquic_str_t */

    // 当前活跃状态的connection id序号
    u_int64_t active_seq;

    // 最大失效connection id序号
    u_int64_t highest_retired;

    // 活跃状态的connection id
    gquic_str_t active_conn_id;

    // 活跃状态的token
    gquic_str_t active_stateless_reset_token;

    // 当前connection id发送的packet数量
    u_int64_t packets_count_since_last_change;

    // 当前connection id发送packet数量的上限
    u_int64_t packets_count_limit;

    // 添加token
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } add_stateless_reset_token;

    // 移除token
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } remove_stateless_reset_token;

    // 失效token
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } retire_stateless_reset_token;

    // 发送控制帧
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, void *const);
    } queue_ctrl_frame;
};

/**
 * 添加token
 *
 * @param manager: 管理模块
 * @param token: token
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_MANAGER_ADD_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->add_stateless_reset_token.cb((manager)->add_stateless_reset_token.self, (token)))

/**
 * 移除token
 *
 * @param manager: 管理模块
 * @param token: token
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_MANAGER_REMOVE_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->remove_stateless_reset_token.cb((manager)->remove_stateless_reset_token.self, (token)))

/**
 * 失效token
 *
 * @param manager: 管理模块
 * @param token: token
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_MANAGER_RETIRE_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->retire_stateless_reset_token.cb((manager)->retire_stateless_reset_token.self, (token)))

/**
 * 发送控制帧
 *
 * @param manager: 管理模块
 * @param token: token
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, frame) \
    ((manager)->queue_ctrl_frame.cb((manager)->queue_ctrl_frame.self, (frame)))

/**
 * connection id管理模块初始化
 *
 * @param manager: 管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_init(gquic_conn_id_manager_t *const manager);

/**
 * 构造connection id管理模块
 *
 * @param manager: 管理模块
 * @param initial_dst_conn_id: QUIC开始握手时的对端connection id
 * @param add_self: 添加connection id回调函数的self参数
 * @param add_cb: 添加connection id回调函数
 * @param remove_self: 移除connection id回调函数的self参数
 * @param remove_cb: 移除connection id回调函数
 * @param retire_self: 失效connection id回调函数的self参数
 * @param retire_cb: 失效connection id回调函数
 * @param queue_ctrl_frame_self: 发送控制帧回调函数的self参数
 * @param queue_ctrl_frame_cb: 发送控制帧回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_ctor(gquic_conn_id_manager_t *const manager,
                                             const gquic_str_t *const initial_dst_conn_id,
                                             void *const add_self, gquic_exception_t (*add_cb)(void *const, const gquic_str_t *const),
                                             void *const remove_self, gquic_exception_t (*remove_cb) (void *const, const gquic_str_t *const),
                                             void *const retire_self, gquic_exception_t (*retire_cb) (void *const, const gquic_str_t *const),
                                             void *const queue_ctrl_frame_self, gquic_exception_t (*queue_ctrl_frame_cb) (void *const, void *const));

/**
 * 添加connection id
 *
 * @param manager: 管理模块
 * @param frame: new connection id frame的内容
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_add(gquic_conn_id_manager_t *const manager, gquic_frame_new_connection_id_t *const frame);

/**
 * 主动关闭
 *
 * @param manager: 管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_close(gquic_conn_id_manager_t *const manager);

/**
 * 更换QUIC开始握手阶段时的connection id
 *
 * @param manager: 管理模块
 * @param conn_id: 新的connection id
 * 
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_change_initial_conn_id(gquic_conn_id_manager_t *const manager, const gquic_str_t *const conn_id);

/**
 * 设置新的token
 *
 * @param manager: 管理模块
 * @param token: token
 * 
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_set_stateless_reset_token(gquic_conn_id_manager_t *const manager, gquic_str_t *const token);

/**
 * 获取connection id
 *
 * @param conn_id: 获取的connection id
 * @param manager: 管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_manager_get_conn_id(gquic_str_t *const conn_id, gquic_conn_id_manager_t *const manager);

#endif

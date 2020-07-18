/* include/packet/conn_id_gen.h connection id 生成模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_CONN_ID_GEN_H
#define _LIBGQUIC_PACKET_CONN_ID_GEN_H

#include "packet/handler.h"
#include "util/rbtree.h"
#include "util/str.h"

/**
 * connection id生成模块
 */
typedef struct gquic_conn_id_gen_s gquic_conn_id_gen_t;
struct gquic_conn_id_gen_s {

    // connection id 长度
    int conn_id_len;

    // 用于生成connection id时唯一ID
    u_int64_t highest_seq;

    // 存储connection id
    gquic_rbtree_t *active_src_conn_ids; /* u_int64_t : gquic_str_t */

    // QUIC握手时的客户端对端connection id
    gquic_str_t initial_cli_dst_conn_id;

    // 新添加一个connection id，并获取对应的token
    struct {
        void *self;
        gquic_exception_t (*cb) (gquic_str_t *const, void *const, const gquic_str_t *const);
    } add_conn_id;

    // 移除一个connection id
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } remove_conn_id;

    // 使一个connection id失效
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const);
    } retire_conn_id;

    // 当关闭一个连接时的相关操作
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, const gquic_str_t *const, gquic_packet_handler_t *const);
    } replace_with_closed;

    // 发送控制帧接口
    struct {
        void *self;
        gquic_exception_t (*cb) (void *const, void *const);
    } queue_ctrl_frame;
};

/**
 * 添加一个connection id，并获取对应的token
 *
 * @param token: 生成的token
 * @param gen: 生成模块
 * @param conn_id: 添加的connection id
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_GEN_ADD_CONN_ID(token, gen, conn_id) \
    ((gen)->add_conn_id.cb((token), (gen)->add_conn_id.self, (conn_id)))

/**
 * 移除一个connection id
 * 
 * @param gen: 生成模块
 * @param conn_id: 移除的connection id
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, conn_id) \
    ((gen)->remove_conn_id.cb((gen)->remove_conn_id.self, (conn_id)))

/**
 * 使一个connection id失效
 *
 * @param gen: 生成模块
 * @param conn_id: 失效的connection id
 * 
 * @return: exception
 */
#define GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, conn_id) \
    ((gen)->retire_conn_id.cb((gen)->retire_conn_id.self, (conn_id)))

/**
 * 关闭一个connection
 *
 * @param gen: 生成模块
 * @param conn_id: connection id
 * @param packet_handler: packet handler
 *
 * @return: exception
 */
#define GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, conn_id, packet_handler) \
    ((gen)->replace_with_closed.cb((gen)->replace_with_closed.self, (conn_id), (packet_handler)))

/**
 * 发送控制帧
 *
 * @param gen: 生成模块
 * @param frame: 控制帧
 *
 * @return: exception
 */
#define GQUIC_CONN_ID_GEN_QUEUE_CTRL_FRAME(gen, frame) \
    ((gen)->queue_ctrl_frame.cb((gen)->queue_ctrl_frame.self, (frame)))

/**
 * 初始化
 * 
 * @param gen: 生成模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_init(gquic_conn_id_gen_t *const gen);

/**
 * 构造生成模块
 *
 * @param gen: 生成模块
 * @param initial_conn_id: QUIC握手开始阶段的connection id
 * @param initial_cli_dst_conn_id: QUIC握手开始阶段客户端对端的connection id
 * @param add_conn_id_self: 添加一个新的connection id回调函数的self参数
 * @param add_conn_id_cb: 添加一个新的connection id回调参数
 * @param remove_conn_id_self: 移除一个connection id回调函数的self参数
 * @param remove_conn_id_cb: 移除一个connection id回调参数
 * @param retrie_conn_id_self: 使一个connection id失效回调函数的self参数
 * @param replace_with_closed_self: 当关闭一个连接时的相关操作回调函数的self参数
 * @param replace_with_closed_cb: 当关闭一个连接时的相关操作回调函数
 * @param queue_ctrl_frame_self: 发送控制帧回调函数的self参数
 * @param queue_ctrl_frame_cb: 发送控制帧回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_ctor(gquic_conn_id_gen_t *const gen,
                                         const gquic_str_t *const initial_conn_id,
                                         const gquic_str_t *const initial_cli_dst_conn_id,
                                         void *const add_conn_id_self,
                                         gquic_exception_t (*add_conn_id_cb) (gquic_str_t *const, void *const, const gquic_str_t *const),
                                         void *const remove_conn_id_self,
                                         gquic_exception_t (*remove_conn_id_cb) (void *const, const gquic_str_t *const),
                                         void *const retrie_conn_id_self,
                                         gquic_exception_t (*retrie_conn_id_cb) (void *const, const gquic_str_t *const),
                                         void *const replace_with_closed_self,
                                         gquic_exception_t (*replace_with_closed_cb) (void *const, const gquic_str_t *const, gquic_packet_handler_t *const),
                                         void *const queue_ctrl_frame_self,
                                         gquic_exception_t (*queue_ctrl_frame_cb) (void *const, void *const));

/**
 * 根据transport parameters中active_connection_id_limit建立对应数目的connection id
 * 
 * @param gen: 生成模块
 * @param limit: 生成connection id的对应个数
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_set_max_active_conn_ids(gquic_conn_id_gen_t *const gen, const u_int64_t limit);

/**
 * 使对应序号的connection id失效
 *
 * @param gen: 生成模块
 * @param seq: connection id的对应序号
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_retire(gquic_conn_id_gen_t *const gen, const u_int64_t seq);

/**
 * QUIC握手阶段完成后的通知（使握手开始阶段的connection id失效）
 *
 * @param gen: 生成模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_set_handshake_complete(gquic_conn_id_gen_t *const gen);

/**
 * 清空所有connection id
 * 
 * @param gen: 生成模块
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_gen_remove_all(gquic_conn_id_gen_t *const gen);

/**
 * 当关闭一个连接时的关联操作
 *
 * @param gen: 生成模块
 * @param closed_handler_alloc: 关闭状态下的packet handler生成回调函数
 * @param self: packet handler生成回调函数的self参数
 */
gquic_exception_t gquic_conn_id_gen_replace_with_closed(gquic_conn_id_gen_t *const gen,
                                                        gquic_exception_t (*closed_handler_alloc) (gquic_packet_handler_t **const handler, void *const self),
                                                        void *const self);

/**
 * 生成一个connection id
 * 
 * @param conn_id: 生成的connection id
 * @param conn_id_len: 生成的connection id长度
 *
 * @return: exception
 */
gquic_exception_t gquic_conn_id_generate(gquic_str_t *const conn_id, const size_t conn_id_len);

#endif

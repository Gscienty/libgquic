/* include/stream/crypto.h QUIC握手阶段数据流控制模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAMS_CRYPTO_H
#define _LIBGQUIC_STREAMS_CRYPTO_H

#include "frame/frame_sorter.h"
#include "frame/crypto.h"
#include "streams/framer.h"
#include "util/str.h"
#include <stdbool.h>

typedef struct gquic_crypto_stream_s gquic_crypto_stream_t;
struct gquic_crypto_stream_s {

    // frame 拼装模块
    gquic_frame_sorter_t sorter;

    // 读取buffer
    gquic_reader_str_t in_reader;
    gquic_str_t in_buf;

    // 读取buffer的数据最大偏移量
    u_int64_t highest_off;

    // 数据流是否已结束
    bool finished;

    // 输出偏移量
    u_int64_t out_off;
    // 输出buffer
    gquic_reader_str_t out_reader;
    gquic_str_t out_buf;
};

/**
 * 初始化数据流控制模块
 *
 * @param str: 数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_init(gquic_crypto_stream_t *const str);

/**
 * 构造数据流控制模块
 *
 * @param str: 数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_ctor(gquic_crypto_stream_t *const str);

/**
 * 数据流控制模块获取传入的CRYPTO frame数据部分
 *
 * @param str: 数据流控制模块
 * @param frame: CRYPTO frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_handle_crypto_frame(gquic_crypto_stream_t *const str, gquic_frame_crypto_t *const frame);

/**
 * 从数据流控制模块中获取传入的数据流
 *
 * @param data: 数据流
 * @param str: 数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_get_data(gquic_str_t *const data, gquic_crypto_stream_t *const str);

/**
 * 标记数据流结束
 *
 * @param str: 数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_finish(gquic_crypto_stream_t *const str);

/**
 * 向数据流控制模块写入数据
 *
 * @param str: 数据流控制模块
 * @param data: 写入数据
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_write(gquic_crypto_stream_t *const str, gquic_reader_str_t *const data);

/**
 * 数据流控制模块中是否仍存在未发送出的数据
 *
 * @param str: 数据流控制模块
 *
 * @return: 是否仍存在未发送出的数据
 */
bool gquic_crypto_stream_has_data(gquic_crypto_stream_t *const str);

/**
 * 从数据流控制模块中提取数据，并封装成一个CRYPTO frame
 * 
 * @param str: 数据流控制模块
 * @param max_len: 数据包载荷最大容量
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_pop_crypto_frame(gquic_frame_crypto_t **frame_storage, gquic_crypto_stream_t *const str, const u_int64_t max_len);


/**
 * handshake阶段完成后， 1rtt加密级别时仍需要传输CRYTPO frame(HANDSHAKE done frame 和 token)
 * 
 * 该模块时后Handshake阶段的数据流控制模块
 */
typedef struct gquic_post_handshake_crypto_stream_s gquic_post_handshake_crypto_stream_t;
struct gquic_post_handshake_crypto_stream_s {

    // 数据流控制模块
    gquic_crypto_stream_t stream;

    // 数据帧发送队列
    gquic_framer_t *framer;
};

/**
 * 初始化数据流控制模块
 *
 * @param str: 数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_post_handshake_crypto_stream_init(gquic_post_handshake_crypto_stream_t *const str);

/**
 * 构造数据流控制模块
 *
 * @param str: 数据流控制模块
 * @param framer: 数据帧发送队列
 *
 * @return: exception
 */
gquic_exception_t gquic_post_handshake_crypto_ctor(gquic_post_handshake_crypto_stream_t *const str, gquic_framer_t *const framer);

/**
 * 向数据流控制模块中写入数据
 *
 * @param str: 数据流控制模块
 * @param reader: 待写入的数据
 *
 * @return: exception
 */
gquic_exception_t gquic_post_handshake_crypto_write(gquic_post_handshake_crypto_stream_t *const str, gquic_reader_str_t *const reader);

/**
 * 统一CRYPTO数据流控制向establish流入的管理模块
 */
typedef struct gquic_crypto_stream_manager_s gquic_crypto_stream_manager_t;
struct gquic_crypto_stream_manager_s {
    struct {
        void *self;
        bool (*cb) (void *const, const gquic_str_t *const, const u_int8_t);
    } handle_msg;

    gquic_crypto_stream_t *initial_stream;
    gquic_crypto_stream_t *handshake_stream;
    gquic_post_handshake_crypto_stream_t *one_rtt_stream;
};

#define GQUIC_CRYPTO_STREAM_MANAGER_HANDLE_MSG(manage, data, enc_lv) \
    ((manage)->handle_msg.cb((manage)->handle_msg.self, (data), (enc_lv)))

/**
 * 初始化流入模块
 *
 * @param manager: 流入模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_manager_init(gquic_crypto_stream_manager_t *const manager);

/**
 * 构造流入模块
 *
 * @param manager: 流入模块
 * @param handle_msg_self: establish
 * @param handle_msg_cb: establish的接收消息回调函数
 * @param initial_stream: initial数据流控制模块
 * @param handshake_stream: handshake数据流控制模块
 * @param one_rtt_stream: 1rtt数据流控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_manager_ctor(gquic_crypto_stream_manager_t *const manager,
                                                   void *handle_msg_self,
                                                   bool (*handle_msg_cb) (void *const, const gquic_str_t *const, const u_int8_t),
                                                   gquic_crypto_stream_t *const initial_stream,
                                                   gquic_crypto_stream_t *const handshake_stream,
                                                   gquic_post_handshake_crypto_stream_t *const one_rtt_stream);

/**
 * 接收一个CRYPTO frame
 * 
 * @param manager: 流入模块
 * @param frame: CRYPTO frame
 * @param enc_lv: 加密级别
 *
 * @return changed: establish是否有更迭变化
 * @return: exception
 */
gquic_exception_t gquic_crypto_stream_manager_handle_crypto_frame(bool *const changed,
                                                                  gquic_crypto_stream_manager_t *const manager,
                                                                  gquic_frame_crypto_t *const frame, const u_int8_t enc_lv);

#endif

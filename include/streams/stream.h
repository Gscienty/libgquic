/* include/stream/stream.h 数据流
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAM_H
#define _LIBGQUIC_STREAM_H

#include "streams/recv_stream.h"
#include "streams/send_stream.h"
#include "streams/stream_sender.h"
#include "exception.h"
#include <pthread.h>

/**
 * 数据流
 */
typedef struct gquic_stream_s gquic_stream_t;
struct gquic_stream_s {
    // 接收数据流
    gquic_recv_stream_t recv;

    // 发送数据流
    gquic_send_stream_t send;

    // 发送与接收的事件接口
    gquic_stream_sender_t *sender;
    gquic_uni_stream_sender_t recv_uni_sender;
    gquic_uni_stream_sender_t send_uni_sender;
    gquic_stream_sender_t recv_sender;
    gquic_stream_sender_t send_sender;

    // 发送与接收是否完成的标记
    pthread_mutex_t completed_mtx;
    bool recv_completed;
    bool send_completed;

    // 流量控制模块
    gquic_flowcontrol_stream_flow_ctrl_t flow_ctrl;
};

/**
 * 初始化数据流
 *
 * @param str: 数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_init(gquic_stream_t *const str);

/**
 * 构造数据流
 *
 * @param str: 数据流
 * @param stream_id: stream id
 * @param sender: 事件接口
 * @param flow_ctrl_ctor_self: 构造流量控制模块self参数
 * @param flow_ctrl_ctor_cb: 构造流量控制模块回调函数
 *
 * @return: exception
 */
gquic_exception_t  gquic_stream_ctor(gquic_stream_t *const str,
                                     const u_int64_t stream_id, gquic_stream_sender_t *const sender, void *const flow_ctrl_ctor_self,
                                     gquic_exception_t  (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t));

/**
 * 析构数据流
 *
 * @param str: 数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_dtor(gquic_stream_t *const str);

/**
 * 关闭数据流
 *
 * @param str: 数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_close(gquic_stream_t *const str);

/**
 * 设定超时时间
 *
 * @param str: 数据流
 * @param deadline: 超时时间
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_set_deadline(gquic_stream_t *const str, const u_int64_t deadline);

/**
 * shutdown
 * 
 * @param str: 数据流
 * @param err: 原因
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_close_for_shutdown(gquic_stream_t *const str, const gquic_exception_t err);

/**
 * 接收RESET_STREAM frame
 * 
 * @param str: 数据流
 * @param frame: RESET_STREAM frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_stream_handle_reset_stream_frame(gquic_stream_t *const str, const gquic_frame_reset_stream_t *const frame);

static inline ssize_t gquic_stream_write(gquic_stream_t *const str, const void *const buf, const size_t size) {
     gquic_reader_str_t reader = { size, (void *) buf };
     gquic_send_stream_write(&str->send, &reader);

     return GQUIC_STR_VAL(&reader) - buf;
}

static inline ssize_t gquic_stream_read(gquic_stream_t *const str, const void *const buf, const size_t size) {
     gquic_writer_str_t writer = { size, (void *) buf };
     gquic_recv_stream_read(&str->recv, &writer);

     return GQUIC_STR_VAL(&writer) - buf;
}

#endif

/* include/stream/recv_stream.h 用于接受的数据流
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAM_RECV_STREAM_H
#define _LIBGQUIC_STREAM_RECV_STREAM_H

#include "frame/frame_sorter.h"
#include "frame/stream.h"
#include "frame/reset_stream.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/stream_sender.h"
#include "coglobal.h"
#include <pthread.h>
#include <sys/types.h>

/**
 * 用于接收的数据流
 */
typedef struct gquic_recv_stream_s gquic_recv_stream_t;
struct gquic_recv_stream_s {
    pthread_mutex_t mtx;

    // stream id
    u_int64_t stream_id;

    // 数据流发送接口
    gquic_stream_sender_t *sender;

    //  frame sorter
    gquic_frame_sorter_t frame_queue;

    // 接收数据读取的偏移量
    u_int64_t read_off;
    // 结束接收数据时的数据偏移量
    u_int64_t final_off;
    // 当前序列化后的frame数据
    gquic_str_t cur_frame;

    // frame处理结束后的回调函数
    struct {
        void *self;
        int (*cb) (void *const);
    } cur_frame_done_cb;

    // 当前序列化后的frame是否为最后一个frame
    bool cur_frame_is_last;

    // 当前frame读取到的位置
    int frame_read_pos;

    bool close_for_shutdown;
    gquic_exception_t close_for_shutdown_reason;

    bool canceled_read;
    gquic_exception_t cancel_read_reason;

    bool reset_remote;
    gquic_exception_t reset_remote_reason;

    // 是否已经读取完毕的标识
    bool fin_read;

    // 读取信号通道
    liteco_channel_t read_chan;

    // 读取超时时间
    u_int64_t deadline;

    // 数据流流量控制模块
    gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl;
};

/**
 * 初始化接收数据流
 *
 * @param str: 接收数据流
 * 
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_init(gquic_recv_stream_t *const str);

/**
 * 构造接收数据流
 *
 * @param str: 接收数据流
 * @param stream_id: stream id
 * @param sender: 数据流发送接口
 * @param flow_ctrl: 数据流流量控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_ctor(gquic_recv_stream_t *const str,
                                         const u_int64_t stream_id, gquic_stream_sender_t *sender, gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl);

/**
 * 析构接收数据流
 *
 * @param str: 接收数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_dtor(gquic_recv_stream_t *const str);

/**
 * 从接收数据流中获取数据
 *
 * @param str: 接收数据流
 * @param writer: writer
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_read(gquic_recv_stream_t *const str, gquic_writer_str_t *const writer);

/**
 * 取消读取操作
 *
 * @param str: 接收数据流
 * @param err_code: 取消读取操作的原因
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_read_cancel(gquic_recv_stream_t *const str, const gquic_exception_t err_code);

/**
 * 接收数据流处理一个发送过来的STREAM frame
 * 
 * @param str: 接收数据流
 * @param stream: STREAM frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_handle_stream_frame(gquic_recv_stream_t *const str, gquic_frame_stream_t *const stream);

/**
 * 接收数据流处理一个发送过来的RESET_STREAM frame
 * 
 * @param str: 接收数据流
 * @param reset_stream: RESET_STREAM frame
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_handle_reset_stream_frame(gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream);

/**
 * 发送一个关闭数据流的STREAM frame到对端
 *
 * @param str: 接收数据流
 * @param off: 关闭时的偏移量
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_close_remote(gquic_recv_stream_t *const str, const u_int64_t off);

/**
 * 设定一个读取超时时间
 *
 * @param str: 接收数据流
 * @param t: 超时时间
 *
 * @return: exception
 */
gquic_exception_t gquic_recv_stream_set_read_deadline(gquic_recv_stream_t *const str, const u_int64_t t);

/**
 * shutdown
 * 
 * @param str: 接收数据流
 * @param err: 关闭原因
 */
gquic_exception_t gquic_recv_stream_close_for_shutdown(gquic_recv_stream_t *const str, const gquic_exception_t err_code);

#endif

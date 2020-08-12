/* include/stream/send_stream.h 用于发送的数据流
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAM_SEND_STREAM_H
#define _LIBGQUIC_STREAM_SEND_STREAM_H

#include <pthread.h>
#include <sys/types.h>
#include "frame/stream.h"
#include "frame/stop_sending.h"
#include "frame/max_stream_data.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/stream_sender.h"
#include "util/list.h"
#include "util/str.h"
#include "coglobal.h"

/**
 * 用于发送的数据流
 */
typedef struct gquic_send_stream_s gquic_send_stream_t;
struct gquic_send_stream_s {
    pthread_mutex_t mtx;

    // stream id
    u_int64_t stream_id;

    // 未被确认接收的STREAM frames个数
    u_int64_t outstanding_frames_count;

    // 重发队列
    gquic_list_t retransmission_queue; /* gquic_frame_stream_t * */

    // STREAM发送后的处理接口
    gquic_stream_sender_t *sender;

    // 发送的偏移量
    u_int64_t write_off;

    bool canceled_write;
    gquic_exception_t canceled_write_reason;

    bool closed_for_shutdown;
    gquic_exception_t close_for_shutdown_reason;

    bool finished_writing;

    bool fin_sent;

    bool completed;

    // 发送数据缓冲区
    gquic_reader_str_t *send_reader;

    // 发送信号
    liteco_channel_t write_chan;

    // 发送超时时间
    u_int64_t deadline;

    // 数据流流量控制模块
    gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl;
};

/**
 * 初始化发送数据流
 *
 * @param str: 发送数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_init(gquic_send_stream_t *const str);

/**
 * 构造发送数据流
 *
 * @param str: 发送数据流
 * @param stream_id: stream id
 * @param sender: 发送后的处理接口
 * @param flow_ctrl: 数据流流量控制模块
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_ctor(gquic_send_stream_t *const str,
                                         const u_int64_t stream_id, gquic_stream_sender_t *const sender, gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl);

/**
 * 发送数据
 *
 * @param str: 发送数据流
 * @param reader: 发送的数据
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_write(gquic_send_stream_t *const str, gquic_reader_str_t *const reader);

/**
 * 获取一个STREAM frame
 * 
 * @param str: 发送数据流
 * @param max_bytes: 能够容纳的最大容量
 *
 * @return frame: STREAM frame
 * @return: 是否有剩余数据
 */
bool gquic_send_stream_pop_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes);

/**
 * 处理STOP_SENDING frame
 *
 * @param str: 发送数据流
 * @param stop_sending: STOP_SENDING frame
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_handle_stop_sending_frame(gquic_send_stream_t *const str, const gquic_frame_stop_sending_t *const stop_sending);

/**
 * 取消发送数据
 *
 * @param str: 发送数据流
 * @param err: 取消发送数据的理由
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_cancel_write(gquic_send_stream_t *const str, const gquic_exception_t err);

/**
 * shutdown
 * 
 * @param str: 发送数据流
 * @param err: shutdown理由
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_close_for_shutdown(gquic_send_stream_t *const str, const gquic_exception_t err);

/**
 * 处理MAX_STREAM_DATA frame
 * 
 * @param str: 发送数据流
 * @param frame: MAX_STREAM_DATA frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_send_stream_handle_max_stream_data_frame(gquic_send_stream_t *const str, gquic_frame_max_stream_data_t *const frame);

/**
 * 关闭发送数据流
 *
 * @param str: 发送数据流
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_close(gquic_send_stream_t *const str);

/**
 * 设置发送超时时间
 *
 * @param str: 发送数据流
 * @param deadline: 超时时间
 *
 * @return: exception
 */
gquic_exception_t gquic_send_stream_set_write_deadline(gquic_send_stream_t *const str, const u_int64_t deadline);

/**
 * 判断发送缓冲区是否仍有数据
 *
 * @param str: 发送数据流
 *
 * @return: 是否仍有数据
 */
static inline bool gquic_send_stream_has_data(gquic_send_stream_t *const str) {
    bool has_data = false;
    if (str == NULL) {
        return false;
    }
    pthread_mutex_lock(&str->mtx);
    has_data = GQUIC_STR_SIZE(str->send_reader) > 0;
    pthread_mutex_unlock(&str->mtx);

    return has_data;
}

#endif

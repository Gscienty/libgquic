/* src/stream/recv_stream.c 用于接受的数据流
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "streams/recv_stream.h"
#include "frame/stop_sending.h"
#include "frame/meta.h"
#include "frame/stream_pool.h"
#include "util/time.h"
#include "exception.h"
#include <string.h>

/**
 * 从 frame_queue中获取一个序列化后的STREAM frame数据流
 *
 * @param str: 接收数据流
 *
 * @return: exception
 */
static inline gquic_exception_t gquic_recv_stream_dequeue_next_frame(gquic_recv_stream_t *const str);

/**
 * 实际从接收数据流中读取模块
 *
 * @param str: 接收数据流
 * @param writer: writer
 *
 * @return completed: 是否完成读取操作
 * @return: exception
 */
static gquic_exception_t gquic_recv_stream_read_inner(bool *const completed, gquic_recv_stream_t *const str, gquic_writer_str_t *const writer);

/**
 * 取消读取
 *
 * @param str: 接收数据流
 * @param err_code: 错误代码
 *
 * @return: 是否成功取消读取操作
 */
static bool gquic_recv_stream_read_cancel_inner(gquic_recv_stream_t *const str, const gquic_exception_t err_code);

/**
 * 处理接收的STREAM frame操作
 *
 * @param str: 接收数据流
 * @param frame: STREAM frame
 * 
 * @return completed: 是否完成
 * @return: exception
 */
static gquic_exception_t gquic_recv_stream_handle_stream_frame_inner(bool *const completed, gquic_recv_stream_t *const str, gquic_frame_stream_t *const frame);

/**
 * 处理接收到RESET STREAM frame的操作
 *
 * @param str: 接收数据流
 * @param frame: RESET STREAM frame
 * 
 * @return completed: 是否完成
 * @return: exception
 */
static gquic_exception_t gquic_recv_stream_handle_reset_stream_frame_inner(bool *const completed, gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const frame);

/**
 * frame 完成操作后的回调函数
 *
 * @param frame: frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_recv_stream_sorter_push_done_cb(void *const frame);

typedef struct gquic_recv_stream_read_param_s gquic_recv_stream_read_param_t;
struct gquic_recv_stream_read_param_s {
    gquic_recv_stream_t *const str;
    gquic_writer_str_t *const writer;
};
static gquic_exception_t gquic_recv_stream_read_co(void *const);

gquic_exception_t gquic_recv_stream_init(gquic_recv_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&str->mtx, NULL);
    str->stream_id = 0;
    str->sender = NULL;
    gquic_frame_sorter_init(&str->frame_queue);
    str->read_off = 0;
    str->final_off = 0;
    gquic_str_init(&str->cur_frame);
    str->cur_frame_done_cb.self = NULL;
    str->cur_frame_done_cb.cb = NULL;
    str->cur_frame_is_last = false;
    str->frame_read_pos = 0;
    str->close_for_shutdown = false;
    str->close_for_shutdown_reason = GQUIC_SUCCESS;
    str->canceled_read = false;
    str->cancel_read_reason = GQUIC_SUCCESS;
    str->reset_remote = false;
    str->reset_remote_reason = GQUIC_SUCCESS;
    str->fin_read = false;
    liteco_channel_init(&str->read_chan);
    str->deadline = 0;
    str->flow_ctrl = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_ctor(gquic_recv_stream_t *const str,
                                         const u_int64_t stream_id, gquic_stream_sender_t *sender, gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str->stream_id = stream_id;
    str->sender = sender;
    str->flow_ctrl = flow_ctrl;
    gquic_frame_sorter_ctor(&str->frame_queue);
    str->final_off = (1UL << 62) - 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_dtor(gquic_recv_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_destroy(&str->mtx);
    gquic_frame_sorter_dtor(&str->frame_queue);
    gquic_str_reset(&str->cur_frame);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_read(gquic_recv_stream_t *const str, gquic_writer_str_t *const writer) {
    liteco_coroutine_t *co = NULL;
    if (str == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    gquic_recv_stream_read_param_t param = {
        .str = str,
        .writer = writer
    };

    gquic_coglobal_currmachine_execute(&co, gquic_recv_stream_read_co, &param);

    GQUIC_PROCESS_DONE(gquic_coglobal_schedule_until_completed(co));
}

static gquic_exception_t gquic_recv_stream_read_co(void *const param_) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    bool completed = false;
    gquic_recv_stream_read_param_t *const param = param_;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_recv_stream_t *const str = param->str;
    gquic_writer_str_t *const writer = param->writer;

    pthread_mutex_lock(&str->mtx);
    GQUIC_ASSERT_CAUSE(exception, gquic_recv_stream_read_inner(&completed, str, writer));
    pthread_mutex_unlock(&str->mtx);

    if (completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_recv_stream_read_cancel(gquic_recv_stream_t *const str, const gquic_exception_t err_code) {
    bool completed = false;
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    completed = gquic_recv_stream_read_cancel_inner(str, err_code);
    pthread_mutex_unlock(&str->mtx);
    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_handle_stream_frame(gquic_recv_stream_t *const str, gquic_frame_stream_t *const frame) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    bool completed = false;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    GQUIC_EXCEPTION_ASSIGN(exception, gquic_recv_stream_handle_stream_frame_inner(&completed, str, frame));
    pthread_mutex_unlock(&str->mtx);

    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }

    GQUIC_PROCESS_DONE(exception);
}

static inline gquic_exception_t gquic_recv_stream_dequeue_next_frame(gquic_recv_stream_t *const str) {
    u_int64_t off = 0;
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str->cur_frame_done_cb.self != NULL) {
        str->cur_frame_done_cb.cb(str->cur_frame_done_cb.self);
    }
    gquic_str_reset(&str->cur_frame);
    gquic_str_init(&str->cur_frame);
    gquic_frame_sorter_pop(&off, &str->cur_frame, &str->cur_frame_done_cb.cb, &str->cur_frame_done_cb.self, &str->frame_queue);
    str->cur_frame_is_last = off + GQUIC_STR_SIZE(&str->cur_frame) >= str->final_off;
    str->frame_read_pos = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_recv_stream_read_inner(bool *const completed, gquic_recv_stream_t *const str, gquic_writer_str_t *const writer) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    u_int64_t read_bytes = 0;
    u_int64_t deadline = 0;
    size_t readed_size = 0;
    const liteco_channel_t *recv_channel = NULL;
    if (completed == NULL || str == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str->fin_read) {
        *completed = false;
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_EOF);
    }
    if (str->canceled_read) {
        *completed = false;
        GQUIC_PROCESS_DONE(str->cancel_read_reason);
    }
    if (str->reset_remote) {
        *completed = false;
        GQUIC_PROCESS_DONE(str->reset_remote_reason);
    }
    if (str->close_for_shutdown) {
        *completed = false;
        GQUIC_PROCESS_DONE(str->close_for_shutdown_reason);
    }
    while (read_bytes < GQUIC_STR_SIZE(writer)) {
        if (GQUIC_STR_SIZE(&str->cur_frame) == 0 || (u_int64_t) str->frame_read_pos >= GQUIC_STR_SIZE(&str->cur_frame)) {
            gquic_recv_stream_dequeue_next_frame(str);
        }
        if (GQUIC_STR_SIZE(&str->cur_frame) == 0 && read_bytes > 0) {
            *completed = false;
            GQUIC_PROCESS_DONE(str->close_for_shutdown_reason);
        }
        for ( ;; ) {
            if (str->close_for_shutdown) {
                *completed = false;
                GQUIC_PROCESS_DONE(str->close_for_shutdown_reason);
            }
            if (str->canceled_read) {
                *completed = false;
                GQUIC_PROCESS_DONE(str->cancel_read_reason);
            }
            if (str->reset_remote) {
                *completed = false;
                GQUIC_PROCESS_DONE(str->reset_remote_reason);
            }
            deadline = str->deadline;
            if (deadline != 0) {
                u_int64_t now = gquic_time_now();
                if (now >= deadline) {
                    *completed = false;
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DEADLINE);
                }
            }
            if (GQUIC_STR_SIZE(&str->cur_frame) != 0 || str->cur_frame_is_last) {
                break;
            }
            pthread_mutex_unlock(&str->mtx);
            GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, deadline, &str->read_chan);
            pthread_mutex_lock(&str->mtx);
            if (GQUIC_STR_SIZE(&str->cur_frame) == 0) {
                gquic_recv_stream_dequeue_next_frame(str);
            }
        }
        if (read_bytes > GQUIC_STR_SIZE(writer)) {
            *completed = false;
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
        }
        if ((size_t) str->frame_read_pos > GQUIC_STR_SIZE(&str->cur_frame)) {
            *completed = false;
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
        }

        pthread_mutex_unlock(&str->mtx);

        readed_size = GQUIC_STR_SIZE(writer) - read_bytes < GQUIC_STR_SIZE(&str->cur_frame) - str->frame_read_pos
            ? GQUIC_STR_SIZE(writer) - read_bytes
            : GQUIC_STR_SIZE(&str->cur_frame) - str->frame_read_pos;
        gquic_str_t buf = { readed_size, GQUIC_STR_VAL(&str->cur_frame) + str->frame_read_pos };
        gquic_writer_str_write(writer, &buf);
        str->frame_read_pos += readed_size;
        read_bytes += readed_size;
        str->read_off += readed_size;

        pthread_mutex_lock(&str->mtx);

        if (!str->reset_remote) {
            gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(str->flow_ctrl, readed_size);
        }
        if ((u_int64_t) str->frame_read_pos >= GQUIC_STR_SIZE(&str->cur_frame) && str->cur_frame_is_last) {
            str->fin_read = true;
            *completed = true;
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_EOF);
        }

    }
    *completed = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static bool gquic_recv_stream_read_cancel_inner(gquic_recv_stream_t *const str, const gquic_exception_t err_code) {
    if (str == NULL) {
        return false;
    }
    gquic_frame_stop_sending_t *stop_sending = NULL;
    if (str->fin_read || str->canceled_read || str->reset_remote) {
        return false;
    }
    str->canceled_read = true;
    str->cancel_read_reason = err_code;
    liteco_channel_send(&str->read_chan, &str->read_chan);
    if (GQUIC_ASSERT(gquic_frame_stop_sending_alloc(&stop_sending))) {
        return false;
    }
    GQUIC_FRAME_INIT(stop_sending);
    stop_sending->errcode = err_code;
    stop_sending->id = str->stream_id;
    GQUIC_SENDER_QUEUE_CTRL_FRAME(str->sender, stop_sending);

    return str->final_off != ((1UL << 62) - 1);
}

static gquic_exception_t gquic_recv_stream_handle_stream_frame_inner(bool *const completed, gquic_recv_stream_t *const str, gquic_frame_stream_t *const frame) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    u_int64_t max_off = 0;
    bool fin = false;
    int newly_recv_final_off = 0;
    if (completed == NULL || str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    max_off = frame->off + GQUIC_STR_SIZE(&frame->data);
    fin = gquic_frame_stream_get_fin(frame);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(str->flow_ctrl, max_off, fin))) {
        *completed = false;
        GQUIC_PROCESS_DONE(exception);
    }
    if (fin) {
        newly_recv_final_off = str->final_off == (1UL << 62) - 1;
        str->final_off = max_off;
    }
    if (str->canceled_read) {
        *completed = newly_recv_final_off;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_frame_sorter_push(&str->frame_queue,
                                                   &frame->data, frame->off,
                                                   gquic_recv_stream_sorter_push_done_cb, frame))) {
        *completed = false;
        GQUIC_PROCESS_DONE(exception);
    }
    liteco_channel_send(&str->read_chan, &str->read_chan);
    *completed = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_recv_stream_sorter_push_done_cb(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_stream_frame_pool_put(frame);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_handle_reset_stream_frame(gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    bool completed = false;
    if (str == NULL || reset_stream == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    GQUIC_ASSERT_CAUSE(exception, gquic_recv_stream_handle_reset_stream_frame_inner(&completed, str, reset_stream));
    pthread_mutex_unlock(&str->mtx);

    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }

    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_recv_stream_handle_reset_stream_frame_inner(bool *const completed, gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (completed == NULL || str == NULL || reset_stream == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str->close_for_shutdown) {
        *completed = 0;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(str->flow_ctrl, reset_stream->final_size, 1))) {
        *completed = 0;
        GQUIC_PROCESS_DONE(exception);
    }
    *completed = str->final_off == (1UL << 62) - 1;
    str->final_off = reset_stream->final_size;
    
    if (str->reset_remote) {
        *completed = 0;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    str->reset_remote = true;
    str->reset_remote_reason = reset_stream->errcode;
    liteco_channel_send(&str->read_chan, &str->read_chan);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_close_remote(gquic_recv_stream_t *const str, const u_int64_t off) {
    gquic_frame_stream_t *stream = NULL;
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_stream_frame_pool_get(&stream));
    GQUIC_FRAME_INIT(stream);
    GQUIC_FRAME_META(stream).type |= 0x01; // FIN
    stream->off = off;

    GQUIC_ASSERT_FAST_RETURN(gquic_recv_stream_handle_stream_frame(str, stream));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_set_read_deadline(gquic_recv_stream_t *const str, const u_int64_t t) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    str->deadline = t;
    pthread_mutex_unlock(&str->mtx);
    liteco_channel_send(&str->read_chan, &str->read_chan);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_recv_stream_close_for_shutdown(gquic_recv_stream_t *const str, const gquic_exception_t err_code) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    str->close_for_shutdown = true;
    str->close_for_shutdown_reason = err_code;
    pthread_mutex_unlock(&str->mtx);
    liteco_channel_send(&str->read_chan, &str->read_chan);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


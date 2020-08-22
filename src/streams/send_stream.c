/* src/stream/send_stream.h 用于发送的数据流
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "streams/send_stream.h"
#include "frame/stream_data_blocked.h"
#include "frame/reset_stream.h"
#include "frame/meta.h"
#include "frame/stream_pool.h"
#include "util/time.h"
#include "exception.h"
#include "log.h"
#include <string.h>

/**
 * 获取要发送的数据填充到STREAM frame中
 *
 * @param frame: STREAM frame
 * @param str: 发送数据流
 * @param data_capacity: 数据容量
 *
 * @return: exception
 */
static gquic_exception_t gquic_send_stream_get_writing_data(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, const u_int64_t data_capacity);

/**
 * 根据发送数据流构造一个新的STREAM frame
 * 
 * @param frame: STREAM frame
 * @param str: 发送数据流
 * @param max_bytes: 最大容量
 *
 * @return: 发送后缓冲区的数据是否仍有剩余
 */
static bool gquic_send_stream_pop_new_stream_frame(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes);

/**
 * 从重发队列中获取STREAM frame
 * 
 * @param str: 发送数据流
 * @param max_bytes: 最大容量
 *
 * @return frame_storage: STREAM frame
 * @return: 重发队列中是否仍有数据
 */
static bool gquic_send_stream_try_retransmission(gquic_frame_stream_t **const frame_storage, gquic_send_stream_t *const str, const u_int64_t max_bytes);

/**
 * 根据发送数据流中待发送的数据或重发队列中获取一个STREAM frame
 *
 * @param str: 发送数据流
 * @param max_bytes: 最大容量
 *
 * @return frame_storage: STREAM frame
 * @return: 发送后数据是否仍有剩余
 */
static bool gquic_send_stream_pop_new_or_retransmission_stream_frame(gquic_frame_stream_t **const frame_storage, gquic_send_stream_t *const str, const u_int64_t max_bytes);

/**
 * 将一个frame添加到重发队列中
 *
 * @param str: 发送数据流
 * @param frame: 数据帧
 *
 * @return: exception
 */
static gquic_exception_t gquic_send_stream_queue_retransmission(gquic_send_stream_t *const str, void *const frame);
static gquic_exception_t gquic_send_stream_queue_retransmission_wrap(void *const, void *const);

/**
 * 处理接收确认数据帧
 *
 * @param str: 发送数据流
 * @param frame: ACK frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_send_stream_frame_acked(gquic_send_stream_t *const str, void *const frame);
static gquic_exception_t gquic_send_stream_frame_acked_wrap(void *const, void *const);

/**
 * 判断是否发送完成
 *
 * @param str: 发送数据流
 *
 * @return: 发送是否完成
 */
inline static bool gquic_send_stream_is_newly_completed(gquic_send_stream_t *const str);

typedef struct gquic_send_stream_write_param_s gquic_send_stream_write_param_t;
struct gquic_send_stream_write_param_s {
    gquic_send_stream_t *const str;
    gquic_reader_str_t *const reader;
};
static gquic_exception_t gquic_send_stream_write_co(void *const);

gquic_exception_t gquic_send_stream_init(gquic_send_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&str->mtx, NULL);
    str->outstanding_frames_count = 0;
    gquic_list_head_init(&str->retransmission_queue);
    str->stream_id = 0;
    str->sender = NULL;
    str->write_off = 0;
    str->canceled_write = false;
    str->close_for_shutdown_reason = 0;
    str->canceled_write_reason = 0;
    str->closed_for_shutdown = false;
    str->finished_writing = false;
    str->fin_sent = false;
    str->completed = false;
    str->send_reader = NULL;
    liteco_channel_init(&str->write_chan);
    str->deadline = 0;
    str->flow_ctrl = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_ctor(gquic_send_stream_t *const str,
                                         const u_int64_t stream_id, gquic_stream_sender_t *const sender, gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str->stream_id = stream_id;
    str->sender = sender;
    str->flow_ctrl = flow_ctrl;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_write(gquic_send_stream_t *const str, gquic_reader_str_t *const reader) {
    liteco_coroutine_t *co = NULL;
    if (str == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    gquic_send_stream_write_param_t param = {
        .str = str,
        .reader = reader
    };

    gquic_coglobal_currmachine_execute(&co, gquic_send_stream_write_co, &param);

    GQUIC_PROCESS_DONE(gquic_coglobal_schedule_until_completed(co));
}

static gquic_exception_t gquic_send_stream_write_co(void *const param_) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_send_stream_write_param_t *const param = param_;
    bool notified_sender = false;
    u_int64_t deadline = 0;
    const liteco_channel_t *recv_channel = NULL;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_send_stream_t *const str = param->str;
    gquic_reader_str_t *const reader = param->reader;

    pthread_mutex_lock(&str->mtx);
    if (str->finished_writing) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_CLOSED);
        goto finished;
    }
    if (str->canceled_write) {
        GQUIC_EXCEPTION_ASSIGN(exception, str->canceled_write_reason);
        goto finished;
    }
    if (str->closed_for_shutdown) {
        GQUIC_EXCEPTION_ASSIGN(exception, str->close_for_shutdown_reason);
        goto finished;
    }
    u_int64_t now = gquic_time_now();
    if (str->deadline != 0 && str->deadline < now) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DEADLINE);
        goto finished;
    }
    if (GQUIC_STR_SIZE(reader) == 0) {
        goto finished;
    }

    str->send_reader = reader;

    GQUIC_LOG(GQUIC_LOG_INFO, "stream send message");

    for ( ;; ) {
        deadline = str->deadline;
        if (deadline != 0) {
            now = gquic_time_now();
            if (deadline < now) {
                goto finished;
            }
        }
        if (GQUIC_STR_SIZE(str->send_reader) == 0 || str->canceled_write || str->closed_for_shutdown) {
            break;
        }
        pthread_mutex_unlock(&str->mtx);
        if (!notified_sender) {
            GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
            notified_sender = true;
        }
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, deadline, &str->write_chan);
        pthread_mutex_lock(&str->mtx);
    }

    if (str->closed_for_shutdown) {
        GQUIC_EXCEPTION_ASSIGN(exception, str->close_for_shutdown_reason);
    }
    else if (str->canceled_write) {
        GQUIC_EXCEPTION_ASSIGN(exception, str->canceled_write_reason);
    }
finished:
    str->send_reader = NULL;
    pthread_mutex_unlock(&str->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_send_stream_get_writing_data(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, u_int64_t max_bytes) {
    u_int64_t tmp = 0;
    if (frame == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(str->send_reader) == 0) {
        if (str->finished_writing && !str->fin_sent) {
            gquic_frame_stream_set_fin(frame);
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    tmp = gquic_flowcontrol_stream_flow_ctrl_swnd_size(str->flow_ctrl);
    max_bytes = max_bytes < tmp ? max_bytes : tmp;
    if (max_bytes == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    gquic_str_reset(&frame->data);
    gquic_str_init(&frame->data);
    if (GQUIC_STR_SIZE(str->send_reader) > max_bytes) {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&frame->data, max_bytes));
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&frame->data, str->send_reader));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&frame->data, GQUIC_STR_SIZE(str->send_reader)));
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&frame->data, str->send_reader));
        liteco_channel_send(&str->write_chan, &str->write_chan);
    }
    str->write_off += GQUIC_STR_SIZE(&frame->data);
    gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(str->flow_ctrl, GQUIC_STR_SIZE(&frame->data));
    if (str->finished_writing && GQUIC_STR_SIZE(str->send_reader) != 0 && !str->fin_sent) {
        gquic_frame_stream_set_fin(frame);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static bool gquic_send_stream_pop_new_stream_frame(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    u_int64_t data_capacity = 0;
    u_int64_t off = 0;
    gquic_frame_stream_data_blocked_t *data_blocked_frame = NULL;
    if (frame == NULL || str == NULL) {
        return false;
    }
    if (str->canceled_write || str->closed_for_shutdown) {
        return false;
    }
    data_capacity = gquic_frame_stream_data_capacity(max_bytes, frame);
    if (data_capacity == 0) {
        return GQUIC_STR_SIZE(str->send_reader) != 0;
    }
    gquic_send_stream_get_writing_data(frame, str, data_capacity);
    if (GQUIC_STR_SIZE(&frame->data) == 0 && !gquic_frame_stream_get_fin(frame)) {
        if (GQUIC_STR_SIZE(str->send_reader) == 0) {
            return false;
        }
        if (gquic_flowcontrol_base_is_newly_blocked(&off, &str->flow_ctrl->base)) {
            if (GQUIC_ASSERT(gquic_frame_stream_data_blocked_alloc(&data_blocked_frame))) {
                return false;
            }
            GQUIC_FRAME_INIT(data_blocked_frame);
            data_blocked_frame->id = str->stream_id;
            data_blocked_frame->limit = off;
            GQUIC_SENDER_QUEUE_CTRL_FRAME(str->sender, data_blocked_frame);
            return false;
        }
        return true;
    }
    if ((GQUIC_FRAME_META(frame).type & 0x01) != 0x00) {
        str->fin_sent = true;
    }
    return GQUIC_STR_SIZE(str->send_reader) != 0;
}

static bool gquic_send_stream_try_retransmission(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    gquic_frame_stream_t *ret_frame = NULL;
    if (frame == NULL || str == NULL) {
        return false;
    }
    ret_frame = *(void **) GQUIC_LIST_FIRST(&str->retransmission_queue);
    if (gquic_frame_stream_split(frame, ret_frame, max_bytes)) {
        return true;
    }
    gquic_list_release(GQUIC_LIST_FIRST(&str->retransmission_queue));
    *frame = ret_frame;
    return !gquic_list_head_empty(&str->retransmission_queue);
}

static bool gquic_send_stream_pop_new_or_retransmission_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    int remain_data = false;
    if (frame == NULL || str == NULL) {
        return false;
    }
    if (!gquic_list_head_empty(&str->retransmission_queue)) {
        if (gquic_send_stream_try_retransmission(frame, str, max_bytes) || *frame != NULL) {
            return true;
        }
    }
    gquic_stream_frame_pool_get(frame);
    GQUIC_FRAME_META(*frame).type |= 0x02;
    GQUIC_FRAME_META(*frame).type |= str->write_off != 0 ? 0x04 : 0x00;
    (*frame)->id = str->stream_id;
    (*frame)->off = str->write_off;
    remain_data = gquic_send_stream_pop_new_stream_frame(*frame, str, max_bytes);
    if (GQUIC_STR_SIZE(&(*frame)->data) == 0 && !gquic_frame_stream_get_fin(*frame)) {
        gquic_stream_frame_pool_put((*frame));
        *frame = NULL;
        return remain_data;
    }
    return remain_data;
}

bool gquic_send_stream_pop_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    bool remain_data = false;
    if (frame == NULL || str == NULL) {
        return false;
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "stream pop stream frame");

    pthread_mutex_lock(&str->mtx);
    remain_data = gquic_send_stream_pop_new_or_retransmission_stream_frame(frame, str, max_bytes);
    if (*frame != NULL) {
        str->outstanding_frames_count++;
    }
    pthread_mutex_unlock(&str->mtx);
    if (*frame == NULL) {
        return remain_data;
    }
    GQUIC_FRAME_META(*frame).on_lost.self = str;
    GQUIC_FRAME_META(*frame).on_lost.cb = gquic_send_stream_queue_retransmission_wrap;
    GQUIC_FRAME_META(*frame).on_acked.self = str;
    GQUIC_FRAME_META(*frame).on_acked.cb = gquic_send_stream_frame_acked_wrap;
    return remain_data;
}

static gquic_exception_t gquic_send_stream_queue_retransmission(gquic_send_stream_t *const str, void *const frame) {
    gquic_frame_stream_t **stream_frame_storage = NULL;
    gquic_frame_stream_t *stream_frame = frame;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_FRAME_META(stream_frame).type |= 0x02;
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &stream_frame_storage, sizeof(gquic_frame_stream_t *)));
    *stream_frame_storage = stream_frame;
    pthread_mutex_lock(&str->mtx);
    gquic_list_insert_before(&str->retransmission_queue, stream_frame_storage);
    str->outstanding_frames_count--;
    if (str->outstanding_frames_count < 0) {
        pthread_mutex_unlock(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    pthread_mutex_unlock(&str->mtx);

    GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_send_stream_queue_retransmission_wrap(void *const str, void *const frame) {
    return gquic_send_stream_queue_retransmission(str, frame);
}

static gquic_exception_t gquic_send_stream_frame_acked(gquic_send_stream_t *const str, void *const frame) {
    bool newly_completed = false;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_stream_frame_pool_put(frame);
    pthread_mutex_lock(&str->mtx);
    str->outstanding_frames_count--;
    if (str->outstanding_frames_count < 0) {
        pthread_mutex_unlock(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    newly_completed = gquic_send_stream_is_newly_completed(str);
    pthread_mutex_unlock(&str->mtx);
    if (newly_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_send_stream_frame_acked_wrap(void *const str, void *const frame) {
    return gquic_send_stream_frame_acked(str, frame);
}

inline static bool gquic_send_stream_is_newly_completed(gquic_send_stream_t *const str) {
    bool completed = false;
    if (str == NULL) {
        return false;
    }
    completed = (str->fin_sent || str->canceled_write) && str->outstanding_frames_count == 0 && gquic_list_head_empty(&str->retransmission_queue);
    if (completed && !str->completed) {
        str->completed = true;
        return true;
    }
    return false;
}

gquic_exception_t gquic_send_stream_handle_stop_sending_frame(gquic_send_stream_t *const str, const gquic_frame_stop_sending_t *const stop_sending) {
    if (str == NULL || stop_sending == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_send_stream_cancel_write(str, stop_sending->errcode);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_cancel_write(gquic_send_stream_t *const str, const gquic_exception_t err) {
    bool newly_completed = false;
    gquic_frame_reset_stream_t *reset_frame = NULL;
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    if (str->canceled_write) {
        pthread_mutex_unlock(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    str->canceled_write = true;
    str->canceled_write_reason = -err;
    newly_completed = gquic_send_stream_is_newly_completed(str);
    pthread_mutex_unlock(&str->mtx);

    liteco_channel_send(&str->write_chan, &str->write_chan);
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_reset_stream_alloc(&reset_frame));
    reset_frame->id = str->stream_id;
    reset_frame->final_size = str->write_off;
    reset_frame->errcode = err;
    if (newly_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_close_for_shutdown(gquic_send_stream_t *const str, const gquic_exception_t err) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    str->canceled_write = true;
    str->canceled_write_reason = err;
    pthread_mutex_unlock(&str->mtx);
    liteco_channel_send(&str->write_chan, &str->write_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_handle_max_stream_data_frame(gquic_send_stream_t *const str, gquic_frame_max_stream_data_t *const frame) {
    bool has_stream_data = false;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    has_stream_data = GQUIC_STR_SIZE(str->send_reader) > 0;
    pthread_mutex_unlock(&str->mtx);

    gquic_flowcontrol_base_update_swnd(&str->flow_ctrl->base, frame->max);
    if (has_stream_data) {
        GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_close(gquic_send_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    if (str->canceled_write) {
        pthread_mutex_unlock(&str->mtx);
        return str->canceled_write_reason;
    }
    str->finished_writing = true;
    pthread_mutex_unlock(&str->mtx);
    GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_send_stream_set_write_deadline(gquic_send_stream_t *const str, const u_int64_t deadline) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->mtx);
    str->deadline = deadline;
    pthread_mutex_unlock(&str->mtx);
    liteco_channel_send(&str->write_chan, &str->write_chan);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


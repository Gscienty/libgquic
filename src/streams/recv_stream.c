#include "streams/recv_stream.h"
#include "frame/stop_sending.h"
#include "frame/meta.h"
#include "frame/stream_pool.h"
#include "exception.h"
#include <string.h>

static inline int gquic_recv_stream_dequeue_next_frame(gquic_recv_stream_t *const);
static int gquic_recv_stream_read_inner(int *const, int *const, gquic_recv_stream_t *const, gquic_str_t *const);
static int gquic_recv_stream_read_cancel_inner(gquic_recv_stream_t *const, const int);
static int gquic_recv_stream_handle_stream_frame_inner(int *const, gquic_recv_stream_t *const, gquic_frame_stream_t *const);
static int gquic_recv_stream_handle_reset_stream_frame_inner(int *const, gquic_recv_stream_t *const, const gquic_frame_reset_stream_t *const);
static int gquic_recv_stream_sorter_push_done_cb(void *const);

int gquic_recv_stream_init(gquic_recv_stream_t *const str) {
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_init(&str->mtx, 0, 1);
    str->stream_id = 0;
    str->sender = NULL;
    gquic_frame_sorter_init(&str->frame_queue);
    str->read_off = 0;
    str->final_off = 0;
    gquic_str_init(&str->cur_frame);
    str->cur_frame_done_cb.self = NULL;
    str->cur_frame_done_cb.cb = NULL;
    str->cur_frame_is_last = 0;
    str->frame_read_pos = 0;
    str->close_for_shutdown_reason = 0;
    str->cancel_read_reason = 0;
    str->reset_remote_reason = 0;
    str->close_for_shutdown = 0;
    str->fin_read = 0;
    str->canceled_read = 0;
    str->reset_remote = 0;
    sem_init(&str->read_sem, 0, 0);
    str->deadline = 0;
    str->flow_ctrl = NULL;

    return GQUIC_SUCCESS;
}

int gquic_recv_stream_ctor(gquic_recv_stream_t *const str,
                           const u_int64_t stream_id,
                           gquic_stream_sender_t *sender,
                           gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    str->stream_id = stream_id;
    str->sender = sender;
    str->flow_ctrl = flow_ctrl;
    gquic_frame_sorter_ctor(&str->frame_queue);
    str->final_off = (1UL << 62) - 1;

    return GQUIC_SUCCESS;
}

int gquic_recv_stream_dtor(gquic_recv_stream_t *const str) {
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_destroy(&str->mtx);
    gquic_frame_sorter_dtor(&str->frame_queue);
    gquic_str_reset(&str->cur_frame);
    sem_destroy(&str->read_sem);

    return GQUIC_SUCCESS;
}

int gquic_recv_stream_read(int *const read, gquic_recv_stream_t *const str, gquic_str_t *const data) {
    int completed = 0;
    int ret = GQUIC_SUCCESS;
    if (read == NULL || str == NULL || data == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    ret = gquic_recv_stream_read_inner(&completed, read, str, data);
    sem_post(&str->mtx);

    if (completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    return ret;
}

int gquic_recv_stream_read_cancel(gquic_recv_stream_t *const str, const int err_code) {
    int completed = 0;
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    completed = gquic_recv_stream_read_cancel_inner(str, err_code);
    sem_post(&str->mtx);
    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    return GQUIC_SUCCESS;
}

int gquic_recv_stream_handle_stream_frame(gquic_recv_stream_t *const str, gquic_frame_stream_t *const frame) {
    int ret = GQUIC_SUCCESS;
    int completed = 0;
    if (str == NULL || frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    ret = gquic_recv_stream_handle_stream_frame_inner(&completed, str, frame);
    sem_post(&str->mtx);

    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    return ret;
}

static inline int gquic_recv_stream_dequeue_next_frame(gquic_recv_stream_t *const str) {
    u_int64_t off = 0;
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (str->cur_frame_done_cb.self != NULL) {
        str->cur_frame_done_cb.cb(str->cur_frame_done_cb.self);
    }
    gquic_str_reset(&str->cur_frame);
    gquic_str_init(&str->cur_frame);
    gquic_frame_sorter_pop(&off, &str->cur_frame, &str->cur_frame_done_cb.cb, &str->cur_frame_done_cb.self, &str->frame_queue);
    str->cur_frame_is_last = off + GQUIC_STR_SIZE(&str->cur_frame) >= str->final_off;
    str->frame_read_pos = 0;

    return GQUIC_SUCCESS;
}

static int gquic_recv_stream_read_inner(int *const completed, int *const read, gquic_recv_stream_t *const str, gquic_str_t *const data) {
    u_int64_t read_bytes = 0;
    u_int64_t deadline = 0;
    size_t readed_size = 0;
    if (completed == NULL || read == NULL || str == NULL || data == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (str->fin_read) {
        *completed = 0;
        *read = 0;
        return GQUIC_EXCEPTION_EOF;
    }
    if (str->canceled_read) {
        *completed = 0;
        *read = 0;
        return str->cancel_read_reason;
    }
    if (str->reset_remote) {
        *completed = 0;
        *read = 0;
        return str->reset_remote_reason;
    }
    if (str->close_for_shutdown) {
        *completed = 0;
        *read = 0;
        return str->close_for_shutdown_reason;
    }
    while (read_bytes < GQUIC_STR_SIZE(data)) {
        if (GQUIC_STR_SIZE(&str->cur_frame) == 0 || (u_int64_t) str->frame_read_pos >= GQUIC_STR_SIZE(&str->cur_frame)) {
            gquic_recv_stream_dequeue_next_frame(str);
        }
        if (GQUIC_STR_SIZE(&str->cur_frame) == 0 && read_bytes > 0) {
            *completed = 0;
            *read = read_bytes;
            return str->close_for_shutdown_reason;
        }
        for ( ;; ) {
            if (str->close_for_shutdown) {
                *completed = 0;
                *read = read_bytes;
                return str->close_for_shutdown_reason;
            }
            if (str->canceled_read) {
                *completed = 0;
                *read = read_bytes;
                return str->cancel_read_reason;
            }
            if (str->reset_remote) {
                *completed = 0;
                *read = read_bytes;
                return str->reset_remote_reason;
            }
            deadline = str->deadline;
            if (deadline != 0) {
                struct timeval tv;
                struct timezone tz;
                gettimeofday(&tv, &tz);
                u_int64_t now = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
                if (now >= deadline) {
                    *completed = 0;
                    *read = read_bytes;
                    return GQUIC_EXCEPTION_DEADLINE;
                }
            }
            if (GQUIC_STR_SIZE(&str->cur_frame) != 0 || str->cur_frame_is_last) {
                break;
            }
            sem_post(&str->mtx);
            if (deadline == 0) {
                sem_wait(&str->read_sem);
            }
            else {
                struct timespec timeout = { deadline / (1000 * 1000), deadline % (1000 * 1000) };
                sem_timedwait(&str->read_sem, &timeout);
            }
            sem_wait(&str->mtx);
            if (GQUIC_STR_SIZE(&str->cur_frame) == 0) {
                gquic_recv_stream_dequeue_next_frame(str);
            }
        }
        if (read_bytes > GQUIC_STR_SIZE(data)) {
            *completed = 0;
            *read = read_bytes;
            return GQUIC_EXCEPTION_INTERNAL_ERROR;
        }
        if ((size_t) str->frame_read_pos > GQUIC_STR_SIZE(&str->cur_frame)) {
            *completed = 0;
            *read = read_bytes;
            return GQUIC_EXCEPTION_INTERNAL_ERROR;
        }

        sem_post(&str->mtx);

        readed_size = GQUIC_STR_SIZE(data) - read_bytes < GQUIC_STR_SIZE(&str->cur_frame) - str->frame_read_pos
            ? GQUIC_STR_SIZE(data) - read_bytes
            : GQUIC_STR_SIZE(&str->cur_frame) - str->frame_read_pos;
        memcpy(GQUIC_STR_VAL(data) + read_bytes,
               GQUIC_STR_VAL(&str->cur_frame) + str->frame_read_pos,
               readed_size);
        str->frame_read_pos += readed_size;
        read_bytes += readed_size;
        str->read_off += readed_size;

        sem_wait(&str->mtx);

        if (!str->reset_remote) {
            gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(str->flow_ctrl, readed_size);
        }
        if ((u_int64_t) str->frame_read_pos >= GQUIC_STR_SIZE(&str->cur_frame) && str->cur_frame_is_last) {
            str->fin_read = 1;
            *completed = 1;
            *read = read_bytes;
            return GQUIC_EXCEPTION_EOF;
        }

    }

    *completed = 1;
    *read = read_bytes;
    return GQUIC_SUCCESS;
}

static int gquic_recv_stream_read_cancel_inner(gquic_recv_stream_t *const str, const int err_code) {
    if (str == NULL) {
        return 0;
    }
    gquic_frame_stop_sending_t *stop_sending = NULL;
    if (str->fin_read || str->canceled_read || str->reset_remote) {
        return 0;
    }
    str->canceled_read = 1;
    str->cancel_read_reason = err_code;
    sem_post(&str->read_sem);
    if ((stop_sending = gquic_frame_stop_sending_alloc()) == NULL) {
        return 0;
    }
    GQUIC_FRAME_INIT(stop_sending);
    stop_sending->errcode = err_code;
    stop_sending->id = str->stream_id;
    GQUIC_SENDER_QUEUE_CTRL_FRAME(str->sender, stop_sending);

    return str->final_off != ((1UL << 62) - 1);
}

static int gquic_recv_stream_handle_stream_frame_inner(int *const completed, gquic_recv_stream_t *const str, gquic_frame_stream_t *const frame) {
    u_int64_t max_off = 0;
    int fin = 0;
    int newly_recv_final_off = 0;
    int exception = GQUIC_SUCCESS;
    if (completed == NULL || str == NULL || frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    max_off = frame->off + GQUIC_STR_SIZE(&frame->data);
    fin = (GQUIC_FRAME_META(frame).type & 0x01) != 0x00;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(str->flow_ctrl, max_off, fin))) {
        *completed = 0;
        return exception;
    }
    if (fin) {
        newly_recv_final_off = str->final_off == (1UL << 62) - 1;
        str->final_off = max_off;
    }
    if (str->canceled_read) {
        *completed = newly_recv_final_off;
        return 0;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_frame_sorter_push(&str->frame_queue,
                                                   &frame->data,
                                                   frame->off,
                                                   gquic_recv_stream_sorter_push_done_cb,
                                                   frame))) {
        *completed = 0;
        return exception;
    }
    sem_post(&str->read_sem);
    *completed = 0;
    return GQUIC_SUCCESS;
}

static int gquic_recv_stream_sorter_push_done_cb(void *const frame) {
    if (frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_stream_frame_pool_put(frame);

    return GQUIC_SUCCESS;
}

int gquic_recv_stream_handle_reset_stream_frame(gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream) {
    int completed = 0;
    int ret = 0;
    if (str == NULL || reset_stream == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    ret = gquic_recv_stream_handle_reset_stream_frame_inner(&completed, str, reset_stream);
    sem_post(&str->mtx);

    if (completed) {
        gquic_flowcontrol_stream_flow_ctrl_abandon(str->flow_ctrl);
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }

    return ret;
}

static int gquic_recv_stream_handle_reset_stream_frame_inner(int *const completed, gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream) {
    int exception = GQUIC_SUCCESS;
    if (completed == NULL || str == NULL || reset_stream == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (str->close_for_shutdown) {
        *completed = 0;
        return GQUIC_SUCCESS;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(str->flow_ctrl, reset_stream->final_size, 1))) {
        *completed = 0;
        return exception;
    }
    *completed = str->final_off == (1UL << 62) - 1;
    str->final_off = reset_stream->final_size;
    
    if (str->reset_remote) {
        *completed = 0;
        return GQUIC_SUCCESS;
    }
    str->reset_remote = 1;
    str->reset_remote_reason = reset_stream->errcode;
    sem_post(&str->read_sem);
    return GQUIC_SUCCESS;
}

int gquic_recv_stream_close_remote(gquic_recv_stream_t *const str, const u_int64_t off) {
    gquic_frame_stream_t *stream = NULL;
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((stream = gquic_frame_stream_alloc()) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    GQUIC_FRAME_INIT(stream);
    GQUIC_FRAME_META(stream).type |= 0x01; // FIN
    stream->off = off;

    GQUIC_ASSERT_FAST_RETURN(gquic_recv_stream_handle_stream_frame(str, stream));
    return GQUIC_SUCCESS;
}

int gquic_recv_stream_set_read_deadline(gquic_recv_stream_t *const str, const u_int64_t t) {
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    str->deadline = t;
    sem_post(&str->mtx);
    sem_post(&str->read_sem);
    return GQUIC_SUCCESS;
}

int gquic_recv_stream_close_for_shutdown(gquic_recv_stream_t *const str, int err) {
    if (str == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&str->mtx);
    str->close_for_shutdown = 1;
    str->close_for_shutdown_reason = err;
    sem_post(&str->mtx);
    sem_post(&str->read_sem);
    return GQUIC_SUCCESS;
}


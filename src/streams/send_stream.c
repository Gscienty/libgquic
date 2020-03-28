#include "streams/send_stream.h"
#include "frame/stream_data_blocked.h"
#include "frame/reset_stream.h"
#include "frame/meta.h"
#include "frame/stream_pool.h"
#include "exception.h"
#include <sys/time.h>
#include <string.h>

static int gquic_send_stream_get_writing_data(gquic_frame_stream_t *const, gquic_send_stream_t *const, u_int64_t);
static int gquic_send_stream_pop_new_stream_frame(gquic_frame_stream_t *const, gquic_send_stream_t *const, const u_int64_t);
static int gquic_send_stream_try_retransmission(gquic_frame_stream_t **const, gquic_send_stream_t *const, const u_int64_t);
static int gquic_send_stream_pop_new_or_retransmission_stream_frame(gquic_frame_stream_t **const, gquic_send_stream_t *const, const u_int64_t);
static int gquic_send_stream_queue_retransmission(gquic_send_stream_t *const, void *const);
static int gquic_send_stream_queue_retransmission_wrap(void *const, void *const);
static int gquic_send_stream_frame_acked(gquic_send_stream_t *const, void *const);
static int gquic_send_stream_frame_acked_wrap(void *const, void *const);
inline static int gquic_send_stream_is_newly_completed(gquic_send_stream_t *const);

int gquic_send_stream_init(gquic_send_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_init(&str->mtx, 0, 1);
    str->outstanding_frames_count = 0;
    gquic_list_head_init(&str->retransmission_queue);
    str->stream_id = 0;
    str->sender = NULL;
    str->write_off = 0;
    str->canceled_write = 0;
    str->close_for_shutdown_reason = 0;
    str->canceled_write_reason = 0;
    str->closed_for_shutdown = 0;
    str->finished_writing = 0;
    str->fin_sent = 0;
    str->completed = 0;
    gquic_str_init(&str->writing_data);
    sem_init(&str->write_sem, 0, 0);
    str->deadline = 0;
    str->flow_ctrl = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_ctor(gquic_send_stream_t *const str,
                           const u_int64_t stream_id,
                           gquic_stream_sender_t *const sender,
                           gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str->stream_id = stream_id;
    str->sender = sender;
    str->flow_ctrl = flow_ctrl;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_write(int *const writed, gquic_send_stream_t *const str, const gquic_str_t *const data) {
    int exception = GQUIC_SUCCESS;
    int notified_sender = 0;
    u_int64_t written_bytes = 0;
    u_int64_t deadline = 0;
    if (writed == NULL || str == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *writed = 0;
    sem_wait(&str->mtx);
    if (str->finished_writing) {
        *writed = 0;
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_CLOSED);
        goto finished;
    }
    if (str->canceled_write) {
        *writed = 0;
        GQUIC_EXCEPTION_ASSIGN(exception, str->canceled_write_reason);
        goto finished;
    }
    if (str->closed_for_shutdown) {
        *writed = 0;
        GQUIC_EXCEPTION_ASSIGN(exception, str->close_for_shutdown_reason);
        goto finished;
    }
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    u_int64_t now = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
    if (str->deadline != 0 && str->deadline < now) {
        *writed = 0;
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DEADLINE);
        goto finished;
    }
    if (GQUIC_STR_SIZE(data) == 0) {
        *writed = 0;
        goto finished;
    }

    gquic_str_reset(&str->writing_data);
    gquic_str_init(&str->writing_data);
    gquic_str_copy(&str->writing_data, data);

    for ( ;; ) {
        written_bytes = GQUIC_STR_SIZE(data) - GQUIC_STR_SIZE(&str->writing_data);
        deadline = str->deadline;
        if (deadline != 0) {
            gettimeofday(&tv, &tz);
            now = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
            if (deadline < now) {
                *writed = written_bytes;
                gquic_str_reset(&str->writing_data);
                gquic_str_init(&str->writing_data);
                goto finished;
            }
        }
        if (GQUIC_STR_SIZE(&str->writing_data) == 0 || str->canceled_write || str->closed_for_shutdown) {
            break;
        }
        sem_post(&str->mtx);
        if (!notified_sender) {
            GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
            notified_sender = 1;
        }
        if (deadline == 0) {
            sem_wait(&str->write_sem);
        }
        else {
            struct timespec timeout = { deadline / (1000 * 1000), deadline % (1000 * 1000) };
            sem_timedwait(&str->write_sem, &timeout);
        }
        sem_wait(&str->mtx);
    }
    if (str->closed_for_shutdown) {
        *writed = written_bytes;
        GQUIC_EXCEPTION_ASSIGN(exception, str->close_for_shutdown_reason);
    }
    else if (str->canceled_write) {
        *writed = written_bytes;
        GQUIC_EXCEPTION_ASSIGN(exception, str->canceled_write_reason);
    }
finished:
    sem_post(&str->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_send_stream_get_writing_data(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, u_int64_t max_bytes) {
    u_int64_t tmp = 0;
    if (frame == NULL || str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&str->writing_data) == 0) {
        GQUIC_FRAME_META(frame).type |= str->finished_writing && !str->fin_sent ? 0x01 : 0x00;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    tmp = gquic_flowcontrol_stream_flow_ctrl_swnd_size(str->flow_ctrl);
    max_bytes = max_bytes < tmp ? max_bytes : tmp;
    if (max_bytes == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    gquic_str_reset(&frame->data);
    gquic_str_init(&frame->data);
    if (GQUIC_STR_SIZE(&str->writing_data) > max_bytes) {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&frame->data, max_bytes));
        memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&str->writing_data), max_bytes);
        memmove(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&frame->data) + max_bytes, GQUIC_STR_SIZE(&frame->data) - max_bytes);
        str->writing_data.size = GQUIC_STR_SIZE(&str->writing_data) - max_bytes;
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&frame->data, GQUIC_STR_SIZE(&str->writing_data)));
        memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&str->writing_data), max_bytes);
        gquic_str_reset(&str->writing_data);
        gquic_str_init(&str->writing_data);
        sem_post(&str->write_sem);
    }
    str->write_off += GQUIC_STR_SIZE(&frame->data);
    gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(str->flow_ctrl, GQUIC_STR_SIZE(&frame->data));
    GQUIC_FRAME_META(frame).type |= str->finished_writing && GQUIC_STR_SIZE(&str->writing_data) && !str->fin_sent ? 0x01 : 0x00;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_send_stream_pop_new_stream_frame(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    u_int64_t data_capacity = 0;
    u_int64_t off = 0;
    gquic_frame_stream_data_blocked_t *data_blocked_frame = NULL;
    if (frame == NULL || str == NULL) {
        return 0;
    }
    if (str->canceled_write || str->closed_for_shutdown) {
        return 0;
    }
    data_capacity = gquic_frame_stream_data_capacity(max_bytes, frame);
    if (data_capacity == 0) {
        return GQUIC_STR_SIZE(&str->writing_data) != 0;
    }
    gquic_send_stream_get_writing_data(frame, str, data_capacity);
    if (GQUIC_STR_SIZE(&frame->data) == 0 && (GQUIC_FRAME_META(frame).type & 0x01) == 0x00) {
        if (GQUIC_STR_SIZE(&str->writing_data) == 0) {
            return 0;
        }
        if (gquic_flowcontrol_base_is_newly_blocked(&off, &str->flow_ctrl->base)) {
            data_blocked_frame = gquic_frame_stream_data_blocked_alloc();
            data_blocked_frame->id = str->stream_id;
            data_blocked_frame->limit = off;
            GQUIC_SENDER_QUEUE_CTRL_FRAME(str->sender, data_blocked_frame);
            return 0;
        }
        return 1;
    }
    if ((GQUIC_FRAME_META(frame).type & 0x01) != 0x00) {
        str->fin_sent = 1;
    }
    return GQUIC_STR_SIZE(&str->writing_data) != 0;
}

static int gquic_send_stream_try_retransmission(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    gquic_frame_stream_t *ret_frame = NULL;
    if (frame == NULL || str == NULL) {
        return 0;
    }
    ret_frame = *(void **) GQUIC_LIST_FIRST(&str->retransmission_queue);
    if (gquic_frame_stream_split(frame, ret_frame, max_bytes)) {
        return 1;
    }
    gquic_list_release(GQUIC_LIST_FIRST(&str->retransmission_queue));
    *frame = ret_frame;
    return !gquic_list_head_empty(&str->retransmission_queue);
}

static int gquic_send_stream_pop_new_or_retransmission_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    int remain_data = 0;
    if (frame == NULL || str == NULL) {
        return 0;
    }
    if (!gquic_list_head_empty(&str->retransmission_queue)) {
        if (gquic_send_stream_try_retransmission(frame, str, max_bytes) || *frame != NULL) {
            return 1;
        }
    }
    gquic_stream_frame_pool_get(frame);
    GQUIC_FRAME_META(*frame).type |= 0x02;
    GQUIC_FRAME_META(*frame).type |= str->write_off != 0 ? 0x04 : 0x00;
    (*frame)->id = str->stream_id;
    (*frame)->off = str->write_off;
    remain_data = gquic_send_stream_pop_new_stream_frame(*frame, str, max_bytes);
    if (GQUIC_STR_SIZE(&(*frame)->data) == 0 && (GQUIC_FRAME_META(*frame).type & 0x01) == 0x00) {
        gquic_stream_frame_pool_put((*frame));
        *frame = NULL;
        return remain_data;
    }
    return remain_data;
}

int gquic_send_stream_pop_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes) {
    int remain_data = 0;
    if (frame == NULL || str == NULL) {
        return 0;
    }
    sem_wait(&str->mtx);
    remain_data = gquic_send_stream_pop_new_or_retransmission_stream_frame(frame, str, max_bytes);
    if (*frame != NULL) {
        str->outstanding_frames_count++;
    }
    sem_post(&str->mtx);
    if (*frame == NULL) {
        return remain_data;
    }
    GQUIC_FRAME_META(*frame).on_lost.self = str;
    GQUIC_FRAME_META(*frame).on_lost.cb = gquic_send_stream_queue_retransmission_wrap;
    GQUIC_FRAME_META(*frame).on_acked.self = str;
    GQUIC_FRAME_META(*frame).on_acked.cb = gquic_send_stream_frame_acked_wrap;
    return remain_data;
}

static int gquic_send_stream_queue_retransmission(gquic_send_stream_t *const str, void *const frame) {
    gquic_frame_stream_t **stream_frame_storage = NULL;
    gquic_frame_stream_t *stream_frame = frame;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_FRAME_META(stream_frame).type |= 0x02;
    if ((stream_frame_storage = gquic_list_alloc(sizeof(gquic_frame_stream_t *))) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    *stream_frame_storage = stream_frame;
    sem_wait(&str->mtx);
    gquic_list_insert_before(&str->retransmission_queue, stream_frame_storage);
    str->outstanding_frames_count--;
    if (str->outstanding_frames_count < 0) {
        sem_post(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    sem_post(&str->mtx);

    GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_send_stream_queue_retransmission_wrap(void *const str, void *const frame) {
    return gquic_send_stream_queue_retransmission(str, frame);
}

static int gquic_send_stream_frame_acked(gquic_send_stream_t *const str, void *const frame) {
    int newly_completed = 0;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_stream_frame_pool_put(frame);
    sem_wait(&str->mtx);
    str->outstanding_frames_count--;
    if (str->outstanding_frames_count < 0) {
        sem_post(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    newly_completed = gquic_send_stream_is_newly_completed(str);
    sem_post(&str->mtx);
    if (newly_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_send_stream_frame_acked_wrap(void *const str, void *const frame) {
    return gquic_send_stream_frame_acked(str, frame);
}

inline static int gquic_send_stream_is_newly_completed(gquic_send_stream_t *const str) {
    int completed = 0;
    if (str == NULL) {
        return 0;
    }
    completed = (str->fin_sent || str->canceled_write) && str->outstanding_frames_count == 0 && gquic_list_head_empty(&str->retransmission_queue);
    if (completed && !str->completed) {
        str->completed = 1;
        return 1;
    }
    return 0;
}

int gquic_send_stream_handle_stop_sending_frame(gquic_send_stream_t *const str, const gquic_frame_stop_sending_t *const stop_sending) {
    if (str == NULL || stop_sending == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_send_stream_cancel_write(str, stop_sending->errcode);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_cancel_write(gquic_send_stream_t *const str, const u_int64_t err) {
    int newly_completed = 0;
    gquic_frame_reset_stream_t *reset_frame = NULL;
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&str->mtx);
    if (str->canceled_write) {
        sem_post(&str->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    str->canceled_write = 1;
    str->canceled_write_reason = -err;
    newly_completed = gquic_send_stream_is_newly_completed(str);
    sem_post(&str->mtx);

    sem_post(&str->write_sem);
    if ((reset_frame = gquic_frame_reset_stream_alloc()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    reset_frame->id = str->stream_id;
    reset_frame->final_size = str->write_off;
    reset_frame->errcode = err;
    if (newly_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_has_data(gquic_send_stream_t *const str) {
    int has_data = 0;
    if (str == NULL) {
        return 0;
    }
    sem_wait(&str->mtx);
    has_data = GQUIC_STR_SIZE(&str->writing_data) > 0;
    sem_post(&str->mtx);
    return has_data;
}

int gquic_send_stream_close_for_shutdown(gquic_send_stream_t *const str, const int err) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&str->mtx);
    str->canceled_write = 1;
    str->canceled_write_reason = err;
    sem_post(&str->mtx);
    sem_post(&str->write_sem);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_handle_max_stream_data_frame(gquic_send_stream_t *const str, gquic_frame_max_stream_data_t *const frame) {
    int has_stream_data = 0;
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&str->mtx);
    has_stream_data = GQUIC_STR_SIZE(&str->writing_data) > 0;
    sem_post(&str->mtx);

    gquic_flowcontrol_base_update_swnd(&str->flow_ctrl->base, frame->max);
    if (has_stream_data) {
        GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_close(gquic_send_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&str->mtx);
    if (str->canceled_write) {
        sem_post(&str->mtx);
        return str->canceled_write_reason;
    }
    str->finished_writing = 1;
    sem_post(&str->mtx);
    GQUIC_SENDER_ON_HAS_STREAM_DATA(str->sender, str->stream_id);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_send_stream_set_write_deadline(gquic_send_stream_t *const str, const u_int64_t deadline) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&str->mtx);
    str->deadline = deadline;
    sem_post(&str->mtx);
    sem_post(&str->write_sem);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

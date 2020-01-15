#include "streams/send_stream.h"
#include "frame/stream_data_blocked.h"
#include "frame/meta.h"
#include <sys/time.h>
#include <string.h>

static int gquic_send_stream_get_writing_data(gquic_frame_stream_t *const, gquic_send_stream_t *const, u_int64_t);
static int gquic_send_stream_pop_new_stream_frame(gquic_frame_stream_t *const, gquic_send_stream_t *const, const u_int64_t);
static int gquic_send_stream_try_retransmission(gquic_frame_stream_t **const, gquic_send_stream_t *const, const u_int64_t);

int gquic_send_stream_init(gquic_send_stream_t *const str) {
    if (str == NULL) {
        return -1;
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

    return 0;
}

int gquic_send_stream_ctor(gquic_send_stream_t *const str,
                           const u_int64_t stream_id,
                           gquic_stream_sender_t *const sender,
                           gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        return -1;
    }
    str->stream_id = stream_id;
    str->sender = sender;
    str->flow_ctrl = flow_ctrl;
    return 0;
}

int gquic_send_stream_write(int *const writed, gquic_send_stream_t *const str, const gquic_str_t *const data) {
    int ret = 0;
    int notified_sender = 0;
    u_int64_t written_bytes = 0;
    u_int64_t deadline = 0;
    if (writed == NULL || str == NULL || data == NULL) {
        return -1;
    }
    *writed = 0;
    sem_wait(&str->mtx);
    if (str->finished_writing) {
        *writed = 0;
        ret = -2;
        goto finished;
    }
    if (str->canceled_write) {
        *writed = 0;
        ret = str->canceled_write_reason;
        goto finished;
    }
    if (str->closed_for_shutdown) {
        *writed = 0;
        ret = str->close_for_shutdown_reason;
        goto finished;
    }
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    u_int64_t now = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
    if (str->deadline != 0 && str->deadline < now) {
        *writed = 0;
        ret = -3;
        goto finished;
    }
    if (GQUIC_STR_SIZE(data) == 0) {
        *writed = 0;
        ret = 0;
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
        ret = str->close_for_shutdown_reason;
    }
    else if (str->canceled_write) {
        *writed = written_bytes;
        ret = str->canceled_write_reason;
    }
finished:
    sem_post(&str->mtx);
    return ret;
}

static int gquic_send_stream_get_writing_data(gquic_frame_stream_t *const frame, gquic_send_stream_t *const str, u_int64_t max_bytes) {
    u_int64_t tmp = 0;
    if (frame == NULL || str == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&str->writing_data) == 0) {
        GQUIC_FRAME_META(frame).type |= str->finished_writing && !str->fin_sent ? 0x01 : 0x00;
        return 0;
    }
    tmp = gquic_flowcontrol_stream_flow_ctrl_swnd_size(str->flow_ctrl);
    max_bytes = max_bytes < tmp ? max_bytes : tmp;
    if (max_bytes == 0) {
        return 0;
    }
    gquic_str_reset(&frame->data);
    gquic_str_init(&frame->data);
    if (GQUIC_STR_SIZE(&str->writing_data) > max_bytes) {
        if (gquic_str_alloc(&frame->data, max_bytes) != 0) {
            return -2;
        }
        memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&str->writing_data), max_bytes);
        memmove(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&frame->data) + max_bytes, GQUIC_STR_SIZE(&frame->data) - max_bytes);
        str->writing_data.size = GQUIC_STR_SIZE(&str->writing_data) - max_bytes;
    }
    else {
        if (gquic_str_alloc(&frame->data, GQUIC_STR_SIZE(&str->writing_data)) != 0) {
            return -2;
        }
        memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&str->writing_data), max_bytes);
        gquic_str_reset(&str->writing_data);
        gquic_str_init(&str->writing_data);
        sem_post(&str->write_sem);
    }
    str->write_off += GQUIC_STR_SIZE(&frame->data);
    gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(str->flow_ctrl, GQUIC_STR_SIZE(&frame->data));
    GQUIC_FRAME_META(frame).type |= str->finished_writing && GQUIC_STR_SIZE(&str->writing_data) && !str->fin_sent ? 0x01 : 0x00;

    return 0;
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


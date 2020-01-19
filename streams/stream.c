#include "streams/stream.h"

static int gquic_stream_sender_for_recv_stream_on_completed(void *const);
static int gquic_stream_sender_for_send_stream_on_completed(void *const);
static int gquic_stream_check_completed(gquic_stream_t *const);

int gquic_stream_init(gquic_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    gquic_recv_stream_init(&str->recv);
    gquic_send_stream_init(&str->send);
    sem_init(&str->completed_mtx, 0, 1);
    gquic_stream_sender_init(str->sender);
    gquic_uni_stream_sender_init(&str->recv_uni_sender);
    gquic_uni_stream_sender_init(&str->send_uni_sender);
    gquic_stream_sender_init(&str->recv_sender);
    gquic_stream_sender_init(&str->send_sender);
    str->recv_completed = 0;
    str->send_completed = 0;

    return 0;
}

int gquic_stream_ctor(gquic_stream_t *const str,
                      const u_int64_t stream_id,
                      gquic_stream_sender_t *const sender,
                      gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl) {
    if (str == NULL || sender == NULL || flow_ctrl == NULL) {
        return -1;
    }
    str->sender = sender;

    str->recv_uni_sender.base = *sender;
    str->recv_uni_sender.on_stream_completed_cb.cb = gquic_stream_sender_for_recv_stream_on_completed;
    str->recv_uni_sender.on_stream_completed_cb.self = str;
    gquic_uni_stream_sender_prototype(&str->recv_sender, &str->recv_uni_sender);
    gquic_recv_stream_ctor(&str->recv, stream_id, &str->recv_sender, flow_ctrl);

    str->send_uni_sender.base = *sender;
    str->send_uni_sender.on_stream_completed_cb.cb = gquic_stream_sender_for_send_stream_on_completed;
    str->send_uni_sender.on_stream_completed_cb.self = str;
    gquic_uni_stream_sender_prototype(&str->send_sender, &str->send_uni_sender);
    gquic_send_stream_ctor(&str->send, stream_id, &str->send_sender, flow_ctrl);

    return 0;
}

int gquic_stream_dtor(gquic_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    // TODO
    return 0;
}

static int gquic_stream_sender_for_recv_stream_on_completed(void *const str_inf) {
    gquic_stream_t *str = str_inf;
    if (str_inf == NULL) {
        return -1;
    }
    sem_wait(&str->completed_mtx);
    str->send_completed = 1;
    gquic_stream_check_completed(str);
    sem_post(&str->completed_mtx);
    return 0;
}

static int gquic_stream_sender_for_send_stream_on_completed(void *const str_inf) {
    gquic_stream_t *str = str_inf;
    if (str_inf == NULL) {
        return -1;
    }
    sem_wait(&str->completed_mtx);
    str->recv_completed = 1;
    gquic_stream_check_completed(str);
    sem_post(&str->completed_mtx);
    return 0;
}

static int gquic_stream_check_completed(gquic_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    if (str->send_completed && str->recv_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->send.stream_id);
    }
    return 0;
}

int gquic_stream_close(gquic_stream_t *const str) {
    if (str == NULL) {
        return -1;
    }
    if (gquic_send_stream_close(&str->send) != 0) {
        return -2;
    }
    return 0;
}

int gquic_stream_set_deadline(gquic_stream_t *const str, const u_int64_t deadline) {
    if (str == NULL) {
        return -1;
    }
    gquic_recv_stream_set_read_deadline(&str->recv, deadline);
    gquic_send_stream_set_write_deadline(&str->send, deadline);
    return 0;
}

int gquic_stream_close_for_shutdown(gquic_stream_t *const str, const int err) {
    if (str == NULL) {
        return -1;
    }
    gquic_send_stream_close_for_shutdown(&str->send, err);
    gquic_recv_stream_close_for_shutdown(&str->recv, err);
    return 0;
}

int gquic_stream_handle_reset_stream_frame(gquic_stream_t *const str, const gquic_frame_reset_stream_t *const frame) {
    if (str == NULL || frame == NULL) {
        return -1;
    }
    gquic_recv_stream_handle_reset_stream_frame(&str->recv, frame);
    return 0;
}

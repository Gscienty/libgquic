#include "streams/stream.h"

static gquic_exception_t gquic_stream_sender_for_recv_stream_on_completed(void *const);
static gquic_exception_t gquic_stream_sender_for_send_stream_on_completed(void *const);
static gquic_exception_t gquic_stream_check_completed(gquic_stream_t *const);

gquic_exception_t gquic_stream_init(gquic_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_recv_stream_init(&str->recv);
    gquic_send_stream_init(&str->send);
    pthread_mutex_init(&str->completed_mtx, NULL);
    str->sender = NULL;
    gquic_uni_stream_sender_init(&str->recv_uni_sender);
    gquic_uni_stream_sender_init(&str->send_uni_sender);
    gquic_stream_sender_init(&str->recv_sender);
    gquic_stream_sender_init(&str->send_sender);
    str->recv_completed = false;
    str->send_completed = false;

    gquic_flowcontrol_stream_flow_ctrl_init(&str->flow_ctrl);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_ctor(gquic_stream_t *const str,
                                    const u_int64_t stream_id,
                                    gquic_stream_sender_t *const sender,
                                    void *const flow_ctrl_ctor_self,
                                    gquic_exception_t (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t)) {
    if (str == NULL || sender == NULL || flow_ctrl_ctor_self == NULL || flow_ctrl_ctor_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    flow_ctrl_ctor_cb(&str->flow_ctrl, flow_ctrl_ctor_self, stream_id);

    str->sender = sender;

    str->recv_uni_sender.base = *sender;
    str->recv_uni_sender.on_stream_completed_cb.cb = gquic_stream_sender_for_recv_stream_on_completed;
    str->recv_uni_sender.on_stream_completed_cb.self = str;
    gquic_uni_stream_sender_prototype(&str->recv_sender, &str->recv_uni_sender);
    gquic_recv_stream_ctor(&str->recv, stream_id, &str->recv_sender, &str->flow_ctrl);

    str->send_uni_sender.base = *sender;
    str->send_uni_sender.on_stream_completed_cb.cb = gquic_stream_sender_for_send_stream_on_completed;
    str->send_uni_sender.on_stream_completed_cb.self = str;
    gquic_uni_stream_sender_prototype(&str->send_sender, &str->send_uni_sender);
    gquic_send_stream_ctor(&str->send, stream_id, &str->send_sender, &str->flow_ctrl);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_dtor(gquic_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    // TODO
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_stream_sender_for_recv_stream_on_completed(void *const str_inf) {
    gquic_stream_t *str = str_inf;
    if (str_inf == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->completed_mtx);
    str->send_completed = true;
    gquic_stream_check_completed(str);
    pthread_mutex_unlock(&str->completed_mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_stream_sender_for_send_stream_on_completed(void *const str_inf) {
    gquic_stream_t *str = str_inf;
    if (str_inf == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str->completed_mtx);
    str->recv_completed = true;
    gquic_stream_check_completed(str);
    pthread_mutex_unlock(&str->completed_mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_stream_check_completed(gquic_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str->send_completed && str->recv_completed) {
        GQUIC_SENDER_ON_STREAM_COMPLETED(str->sender, str->send.stream_id);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_close(gquic_stream_t *const str) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    return gquic_send_stream_close(&str->send);
}

gquic_exception_t gquic_stream_set_deadline(gquic_stream_t *const str, const u_int64_t deadline) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_recv_stream_set_read_deadline(&str->recv, deadline);
    gquic_send_stream_set_write_deadline(&str->send, deadline);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_close_for_shutdown(gquic_stream_t *const str, const gquic_exception_t err) {
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_send_stream_close_for_shutdown(&str->send, err);
    gquic_recv_stream_close_for_shutdown(&str->recv, err);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_stream_handle_reset_stream_frame(gquic_stream_t *const str, const gquic_frame_reset_stream_t *const frame) {
    if (str == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_recv_stream_handle_reset_stream_frame(&str->recv, frame);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

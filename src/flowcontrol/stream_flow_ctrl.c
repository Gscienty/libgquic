#include "flowcontrol/stream_flow_ctrl.h"
#include "exception.h"

static inline int gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const);

int gquic_flowcontrol_stream_flow_ctrl_init(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_flowcontrol_base_init(&ctrl->base);
    ctrl->stream_id = 0;
    ctrl->queue_wnd_update.cb = NULL;
    ctrl->queue_wnd_update.self = NULL;
    ctrl->conn_flow_ctrl = NULL;
    ctrl->recv_final_off = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
int gquic_flowcontrol_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                            const u_int64_t stream_id,
                                            gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl,
                                            const u_int64_t rwnd,
                                            const u_int64_t max_rwnd,
                                            const u_int64_t initial_swnd,
                                            void *const queue_wnd_update_self,
                                            int (*queue_wnd_update_cb) (void *const, const u_int64_t),
                                            gquic_rtt_t *const rtt) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ctrl->stream_id = stream_id;
    ctrl->conn_flow_ctrl = conn_flow_ctrl;
    ctrl->queue_wnd_update.cb = queue_wnd_update_cb;
    ctrl->queue_wnd_update.self = queue_wnd_update_self;
    ctrl->base.rtt = rtt;
    ctrl->base.rwnd = rwnd;
    ctrl->base.rwnd_size = rwnd;
    ctrl->base.max_rwnd_size = max_rwnd;
    ctrl->base.swnd = initial_swnd;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_flowcontrol_stream_flow_ctrl_dtor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_flowcontrol_base_dtor(&ctrl->base);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl, const u_int64_t off, int final) {
    int exception = GQUIC_SUCCESS;
    u_int64_t increment = 0;
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&ctrl->base.mtx);
    if (ctrl->recv_final_off) {
        if (final && off != ctrl->base.highest_recv) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_INCONSISTENT_FINAL);
            goto failure;
        }
        if (off > ctrl->base.highest_recv) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_INCONSISTENT_FINAL);
            goto failure;
        }
    }
    if (final) {
        ctrl->recv_final_off = 1;
    }
    if (off == ctrl->base.highest_recv) {
        goto finished;
    }
    if (off <= ctrl->base.highest_recv) {
        if (final) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_INCONSISTENT_FINAL);
            goto failure;
        }
        goto finished;
    }
    increment = off - ctrl->base.highest_recv;
    ctrl->base.highest_recv = off;
    if (ctrl->base.highest_recv > ctrl->base.rwnd) {
        exception = GQUIC_EXCEPTION_FLOW_CTRL_DISALLOW_RECV;
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(ctrl->conn_flow_ctrl, increment))) {
        goto failure;
    }

finished:
    sem_post(&ctrl->base.mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    sem_post(&ctrl->base.mtx);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl, const u_int64_t n) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_flowcontrol_base_read_add_bytes(&ctrl->base, n);
    gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(ctrl);
    gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(ctrl->conn_flow_ctrl, n);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    int has_wnd_update = 0;
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&ctrl->base.mtx);
    has_wnd_update = !ctrl->recv_final_off && gquic_flowcontrol_base_has_wnd_update(&ctrl->base);
    sem_post(&ctrl->base.mtx);
    if (has_wnd_update) {
        GQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_flowcontrol_stream_flow_ctrl_abandon(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t unread = 0;
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    unread = ctrl->base.highest_recv - ctrl->base.read_bytes;
    if (unread > 0) {
        gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(ctrl->conn_flow_ctrl, unread);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl, const u_int64_t n) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_flowcontrol_base_sent_add_bytes(&ctrl->base, n);
    gquic_flowcontrol_base_sent_add_bytes(&ctrl->conn_flow_ctrl->base, n);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_flowcontrol_stream_flow_ctrl_swnd_size(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t self_swnd_size = 0;
    u_int64_t conn_swnd_size = 0;
    if (ctrl == NULL) {
        return 0;
    }
    self_swnd_size = gquic_flowcontrol_base_swnd_size(&ctrl->base);
    conn_swnd_size = gquic_flowcontrol_conn_flow_ctrl_swnd_size(ctrl->conn_flow_ctrl);

    return self_swnd_size < conn_swnd_size ? self_swnd_size : conn_swnd_size;
}

u_int64_t gquic_flowcontrol_stream_flow_ctrl_get_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t old_wnd_size = 0;
    u_int64_t off = 0;
    if (ctrl == NULL) {
        return 0;
    }
    sem_wait(&ctrl->base.mtx);
    if (ctrl->recv_final_off) {
        sem_post(&ctrl->base.mtx);
        return 0;
    }
    old_wnd_size = ctrl->base.rwnd_size;
    off = gquic_flowcontrol_base_get_wnd_update(&ctrl->base);
    if (ctrl->base.rwnd_size > old_wnd_size) {
        gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(ctrl->conn_flow_ctrl, ctrl->base.rwnd_size * 1.5);
    }
    sem_post(&ctrl->base.mtx);

    return off;
}

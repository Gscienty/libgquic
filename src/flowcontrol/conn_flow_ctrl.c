#include "flowcontrol/conn_flow_ctrl.h"
#include "exception.h"

static inline int gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const);

int gquic_flowcontrol_conn_flow_ctrl_init(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_flowcontrol_base_init(&ctrl->base);
    ctrl->queue_wnd_update.cb = NULL;
    ctrl->queue_wnd_update.self = NULL;

    return GQUIC_SUCCESS;
}

int gquic_flowcontrol_conn_flow_ctrl_ctor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                          const u_int64_t rwnd,
                                          const u_int64_t max_rwnd,
                                          void *queue_wnd_update_self,
                                          int (*queue_wnd_update_cb) (void *const),
                                          gquic_rtt_t *const rtt) {
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    ctrl->base.rtt = rtt;
    ctrl->base.rwnd = rwnd;
    ctrl->base.rwnd_size = rwnd;
    ctrl->base.max_rwnd_size = max_rwnd;
    ctrl->queue_wnd_update.cb = queue_wnd_update_cb;
    ctrl->queue_wnd_update.self = queue_wnd_update_self;

    return GQUIC_SUCCESS;
}

int gquic_flowcontrol_conn_flow_ctrl_dtor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return GQUIC_SUCCESS;
    }
    gquic_flowcontrol_base_dtor(&ctrl->base);
    return GQUIC_SUCCESS;
}

u_int64_t gquic_flowcontrol_conn_flow_ctrl_swnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return 0;
    }
    return gquic_flowcontrol_base_swnd_size(&ctrl->base);
}

int gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                                            const u_int64_t increment) {
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&ctrl->base.mtx);
    ctrl->base.highest_recv += increment;
    if (ctrl->base.highest_recv > ctrl->base.rwnd) {
        sem_post(&ctrl->base.mtx);
        return GQUIC_EXCEPTION_FLOW_CTRL_DISALLOW_RECV;
    }
    sem_post(&ctrl->base.mtx);
    return GQUIC_SUCCESS;
}

int gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                                    const u_int64_t n) {
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_flowcontrol_base_read_add_bytes(&ctrl->base, n);
    gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(ctrl);
    return GQUIC_SUCCESS;
}

static inline int gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    int has_wnd_update = 0;
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&ctrl->base.mtx);
    has_wnd_update = gquic_flowcontrol_base_has_wnd_update(&ctrl->base);
    sem_post(&ctrl->base.mtx);
    if (has_wnd_update) {
        GQUIC_FLOWCONTROL_CONN_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl);
    }
    return GQUIC_SUCCESS;
}

u_int64_t gquic_flowcontrol_conn_flow_ctrl_get_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    u_int64_t off = 0;
    if (ctrl == NULL) {
        return 0;
    }
    sem_wait(&ctrl->base.mtx);
    off = gquic_flowcontrol_base_get_wnd_update(&ctrl->base);
    sem_post(&ctrl->base.mtx);
    return off;
}

int gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t inc) {
    if (ctrl == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&ctrl->base.mtx);
    if (inc > ctrl->base.rwnd_size) {
        ctrl->base.rwnd_size = inc < ctrl->base.max_rwnd_size ? inc : ctrl->base.max_rwnd_size;
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        ctrl->base.epoch_time = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
        ctrl->base.epoch_off = ctrl->base.read_bytes;
    }
    sem_post(&ctrl->base.mtx);
    return GQUIC_SUCCESS;
}

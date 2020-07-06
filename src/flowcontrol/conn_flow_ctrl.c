/* src/flowcontrol/conn_flow_ctrl.c 连接流量控制模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "flowcontrol/conn_flow_ctrl.h"
#include "exception.h"

/**
 * 尝试更新接收窗口（调用更新接收窗口的回调函数）
 *
 * @param ctrl: ctrl
 * 
 * @return: exception
 */
static inline gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_init(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_flowcontrol_base_init(&ctrl->base);
    ctrl->queue_wnd_update.cb = NULL;
    ctrl->queue_wnd_update.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_ctor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                                        const u_int64_t rwnd,
                                                        const u_int64_t max_rwnd,
                                                        void *queue_wnd_update_self,
                                                        int (*queue_wnd_update_cb) (void *const),
                                                        gquic_rtt_t *const rtt) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ctrl->base.rtt = rtt;
    ctrl->base.rwnd = rwnd;
    ctrl->base.rwnd_size = rwnd;
    ctrl->base.max_rwnd_size = max_rwnd;
    ctrl->queue_wnd_update.cb = queue_wnd_update_cb;
    ctrl->queue_wnd_update.self = queue_wnd_update_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_dtor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    gquic_flowcontrol_base_dtor(&ctrl->base);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t increment) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&ctrl->base.mtx);
    ctrl->base.highest_recv += increment;

    // 当最大接收窗口大于接收窗口时，将报错 : FLOW_CTRL_DISALLOW_RECV
    if (ctrl->base.highest_recv > ctrl->base.rwnd) {
        pthread_mutex_unlock(&ctrl->base.mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FLOW_CTRL_DISALLOW_RECV);
    }
    pthread_mutex_unlock(&ctrl->base.mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t bytes) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    gquic_flowcontrol_base_read_add_bytes(&ctrl->base, bytes);
    gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(ctrl);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    int has_wnd_update = 0;
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&ctrl->base.mtx);
    has_wnd_update = gquic_flowcontrol_base_has_wnd_update(&ctrl->base);
    pthread_mutex_unlock(&ctrl->base.mtx);
    if (has_wnd_update) {
        GQUIC_FLOWCONTROL_CONN_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_flowcontrol_conn_flow_ctrl_get_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl) {
    u_int64_t off = 0;
    if (ctrl == NULL) {
        return 0;
    }
    pthread_mutex_lock(&ctrl->base.mtx);
    off = gquic_flowcontrol_base_get_wnd_update(&ctrl->base);
    pthread_mutex_unlock(&ctrl->base.mtx);

    return off;
}

gquic_exception_t gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t rwnd_size) {
    if (ctrl == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&ctrl->base.mtx);
    if (rwnd_size > ctrl->base.rwnd_size) {
        ctrl->base.rwnd_size = rwnd_size < ctrl->base.max_rwnd_size ? rwnd_size : ctrl->base.max_rwnd_size;
        ctrl->base.epoch_time = gquic_time_now();
        ctrl->base.epoch_off = ctrl->base.read_bytes;
    }
    pthread_mutex_unlock(&ctrl->base.mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

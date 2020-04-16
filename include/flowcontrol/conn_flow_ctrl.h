#ifndef _LIBGQUIC_FLOWCONTROL_CONN_FLOW_CTRL_H
#define _LIBGQUIC_FLOWCONTROL_CONN_FLOW_CTRL_H

#include "flowcontrol/base.h"

typedef struct gquic_flowcontrol_conn_flow_ctrl_s gquic_flowcontrol_conn_flow_ctrl_t;
struct gquic_flowcontrol_conn_flow_ctrl_s {
    gquic_flowcontrol_base_t base;
    struct {
        void *self;
        int (*cb) (void *const);
    } queue_wnd_update;
};

#define GQUIC_FLOWCONTROL_CONN_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl) ((ctrl)->queue_wnd_update.cb((ctrl)->queue_wnd_update.self))

int gquic_flowcontrol_conn_flow_ctrl_init(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_conn_flow_ctrl_ctor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl,
                                          const u_int64_t rwnd,
                                          const u_int64_t max_rwnd,
                                          void *queue_wnd_update_self,
                                          int (*queue_wnd_update_cb) (void *const),
                                          gquic_rtt_t *const rtt);
int gquic_flowcontrol_conn_flow_ctrl_dtor(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);
u_int64_t gquic_flowcontrol_conn_flow_ctrl_swnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t increment);
int gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t n);
u_int64_t gquic_flowcontrol_conn_flow_ctrl_get_wnd_update(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(gquic_flowcontrol_conn_flow_ctrl_t *const ctrl, const u_int64_t inc);

#endif

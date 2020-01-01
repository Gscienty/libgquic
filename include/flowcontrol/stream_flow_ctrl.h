#ifndef _LIBGQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_H
#define _LIBGQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_H

#include "flowcontrol/base.h"
#include "flowcontrol/conn_flow_ctrl.h"

typedef struct gquic_flowcontrol_stream_flow_ctrl_s gquic_flowcontrol_stream_flow_ctrl_t;
struct gquic_flowcontrol_stream_flow_ctrl_s {
    gquic_flowcontrol_base_t base;
    u_int64_t stream_id;
    struct {
        void *self;
        int (*cb) (void *const, const u_int64_t);
    } queue_wnd_update;
    gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl;
    int recv_final_off;
};

#define GQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl) ((ctrl)->queue_wnd_update.cb((ctrl)->queue_wnd_update.self, (ctrl)->stream_id))

int gquic_flowcontrol_stream_flow_ctrl_init(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                            const u_int64_t stream_id,
                                            gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl,
                                            const u_int64_t rwnd,
                                            const u_int64_t max_rwnd,
                                            const u_int64_t initial_swnd,
                                            void *const queue_wnd_update_self,
                                            int (*queue_wnd_update_cb) (void *const, const u_int64_t),
                                            gquic_rtt_t *const rtt);
int gquic_flowcontrol_stream_flow_ctrl_dtor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                           const u_int64_t off,
                                                           int final);
int gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                      const u_int64_t n);
int gquic_flowcontrol_stream_flow_ctrl_abandon(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);
int gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                      const u_int64_t n);
u_int64_t gquic_flowcontrol_stream_flow_ctrl_swnd_size(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);
u_int64_t gquic_flowcontrol_stream_flow_ctrl_get_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl);

#endif

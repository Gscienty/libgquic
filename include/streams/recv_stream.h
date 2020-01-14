#ifndef _LIBGQUIC_STREAM_RECV_STREAM_H
#define _LIBGQUIC_STREAM_RECV_STREAM_H

#include <semaphore.h>
#include <sys/types.h>
#include "frame/frame_sorter.h"
#include "frame/stream.h"
#include "frame/reset_stream.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/stream_sender.h"

typedef struct gquic_recv_stream_s gquic_recv_stream_t;
struct gquic_recv_stream_s {
    sem_t mtx;
    u_int64_t stream_id;
    gquic_stream_sender_t *sender;
    gquic_frame_sorter_t frame_queue;
    u_int64_t read_off;
    u_int64_t final_off;
    gquic_str_t cur_frame;
    struct {
        void *self;
        int (*cb) (void *const);
    } cur_frame_done_cb;
    int cur_frame_is_last;
    int frame_read_pos;
    int close_for_shutdown_reason;
    int cancel_read_reason;
    int reset_remote_reason;
    int close_for_shutdown;
    int fin_read;
    int canceled_read;
    int reset_remote;
    sem_t read_sem;
    u_int64_t deadline;
    gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl;
};

int gquic_recv_stream_init(gquic_recv_stream_t *const str);
int gquic_recv_stream_ctor(gquic_recv_stream_t *const str,
                           const u_int64_t stream_id,
                           gquic_stream_sender_t *sender,
                           gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl);
int gquic_recv_stream_dtor(gquic_recv_stream_t *const str);
int gquic_recv_stream_read(int *const read, gquic_recv_stream_t *const str, gquic_str_t *const data);
int gquic_recv_stream_read_cancel(gquic_recv_stream_t *const str, const int err_code);
int gquic_recv_stream_handle_stream_frame(gquic_recv_stream_t *const str, gquic_frame_stream_t *const stream);
int gquic_recv_stream_handle_reset_stream_frame(gquic_recv_stream_t *const str, const gquic_frame_reset_stream_t *const reset_stream);
int gquic_recv_stream_close_remote(gquic_recv_stream_t *const str, const u_int64_t off);
int gquic_recv_stream_set_read_deadline(gquic_recv_stream_t *const str, const u_int64_t t);
int gquic_recv_stream_close_for_shutdown(gquic_recv_stream_t *const str, int err);

#endif

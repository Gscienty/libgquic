#ifndef _LIBGQUIC_STREAM_SEND_STREAM_H
#define _LIBGQUIC_STREAM_SEND_STREAM_H

#include <semaphore.h>
#include <sys/types.h>
#include "frame/stream.h"
#include "frame/stop_sending.h"
#include "frame/max_stream_data.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "streams/stream_sender.h"
#include "util/list.h"
#include "util/str.h"

typedef struct gquic_send_stream_s gquic_send_stream_t;
struct gquic_send_stream_s {
    sem_t mtx;
    u_int64_t outstanding_frames_count;
    gquic_list_t retransmission_queue; /* gquic_frame_stream_t * */
    u_int64_t stream_id;
    gquic_stream_sender_t *sender;
    u_int64_t write_off;
    int canceled_write_reason;
    int close_for_shutdown_reason;
    int canceled_write;
    int closed_for_shutdown;
    int finished_writing;
    int fin_sent;
    int completed;
    gquic_str_t writing_data;
    sem_t write_sem;
    u_int64_t deadline;
    gquic_flowcontrol_stream_flow_ctrl_t *flow_ctrl;
};

int gquic_send_stream_init(gquic_send_stream_t *const str);
int gquic_send_stream_ctor(gquic_send_stream_t *const str,
                           const u_int64_t stream_id,
                           gquic_stream_sender_t *const sender,
                           gquic_flowcontrol_stream_flow_ctrl_t *const flow_ctrl);
int gquic_send_stream_write(gquic_send_stream_t *const str, gquic_writer_str_t *const writer);
int gquic_send_stream_pop_stream_frame(gquic_frame_stream_t **const frame, gquic_send_stream_t *const str, const u_int64_t max_bytes);
int gquic_send_stream_handle_stop_sending_frame(gquic_send_stream_t *const str, const gquic_frame_stop_sending_t *const stop_sending);
int gquic_send_stream_cancel_write(gquic_send_stream_t *const str, const u_int64_t err);
int gquic_send_stream_has_data(gquic_send_stream_t *const str);
int gquic_send_stream_close_for_shutdown(gquic_send_stream_t *const str, const int err);
int gquic_send_stream_handle_max_stream_data_frame(gquic_send_stream_t *const str, gquic_frame_max_stream_data_t *const frame);
int gquic_send_stream_close(gquic_send_stream_t *const str);
int gquic_send_stream_set_write_deadline(gquic_send_stream_t *const str, const u_int64_t deadline);

#endif

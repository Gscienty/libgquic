#include "streams/send_stream.h"

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

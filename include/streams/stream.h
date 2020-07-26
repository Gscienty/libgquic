#ifndef _LIBGQUIC_STREAM_H
#define _LIBGQUIC_STREAM_H

#include "streams/recv_stream.h"
#include "streams/send_stream.h"
#include "streams/stream_sender.h"
#include <semaphore.h>

typedef struct gquic_stream_s gquic_stream_t;
struct gquic_stream_s {
    gquic_recv_stream_t recv;
    gquic_send_stream_t send;

    sem_t completed_mtx;
    gquic_stream_sender_t *sender;
    gquic_uni_stream_sender_t recv_uni_sender;
    gquic_uni_stream_sender_t send_uni_sender;
    gquic_stream_sender_t recv_sender;
    gquic_stream_sender_t send_sender;

    int recv_completed;
    int send_completed;

    gquic_flowcontrol_stream_flow_ctrl_t flow_ctrl;
};

int gquic_stream_init(gquic_stream_t *const str);
int gquic_stream_ctor(gquic_stream_t *const str,
                      const u_int64_t stream_id,
                      gquic_stream_sender_t *const sender,
                      void *const flow_ctrl_ctor_self,
                      int (*flow_ctrl_ctor_cb) (gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t));
int gquic_stream_dtor(gquic_stream_t *const str);
int gquic_stream_close(gquic_stream_t *const str);
int gquic_stream_set_deadline(gquic_stream_t *const str, const u_int64_t deadline);
int gquic_stream_close_for_shutdown(gquic_stream_t *const str, const int err);
int gquic_stream_handle_reset_stream_frame(gquic_stream_t *const str, const gquic_frame_reset_stream_t *const frame);

#define gquic_stream_write(stream, buf, size) \
    ({\
     gquic_reader_str_t reader = { size, buf }; \
     gquic_send_stream_write(&(stream)->send, &reader); \
     })
#define gquic_stream_read(stream, buf, size) \
    ({\
     gquic_writer_str_t writer = { size, buf }; \
     gquic_recv_stream_read(&(stream)->recv, &writer); \
     })

#endif

#ifndef _LIBGQUIC_STREAMS_STREAM_SENDER_H
#define _LIBGQUIC_STREAMS_STREAM_SENDER_H

#include <sys/types.h>

typedef struct gquic_stream_sender_s gquic_stream_sender_t;
struct gquic_stream_sender_s {
    void *self;
    int (*queue_ctrl_frame) (void *const, void *const);
    int (*on_has_stream_data) (void *const, const u_int64_t);
    int (*on_stream_completed) (void *const, const u_int64_t);
};
int gquic_stream_sender_init(gquic_stream_sender_t *const sender);

typedef struct gquic_uni_stream_sender_s gquic_uni_stream_sender_t;
struct gquic_uni_stream_sender_s {
    gquic_stream_sender_t base;
    struct {
        void *self;
        int (*cb) (void *const);
    } on_stream_completed_cb;
};
int gquic_uni_stream_sender_init(gquic_uni_stream_sender_t *const sender);
int gquic_uni_stream_sender_prototype(gquic_stream_sender_t *const prototype, gquic_uni_stream_sender_t *const sender);

#endif

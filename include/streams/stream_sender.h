#ifndef _LIBGQUIC_STREAMS_STREAM_SENDER_H
#define _LIBGQUIC_STREAMS_STREAM_SENDER_H

#include <sys/types.h>
#include "exception.h"

typedef struct gquic_stream_sender_s gquic_stream_sender_t;
struct gquic_stream_sender_s {
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_ctrl_frame;
    struct {
        void *self;
        int (*cb) (void *const, const u_int64_t);
    } on_has_stream_data;
    struct {
        void *self;
        int (*cb) (void *const, const u_int64_t);
    } on_stream_completed;
};
int gquic_stream_sender_init(gquic_stream_sender_t *const sender);

#define GQUIC_SENDER_QUEUE_CTRL_FRAME(sender, frame) \
    (((sender)->queue_ctrl_frame.self) == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : ((sender)->queue_ctrl_frame.cb((sender)->queue_ctrl_frame.self, (frame))))
#define GQUIC_SENDER_ON_HAS_STREAM_DATA(sender, sid) \
    (((sender)->on_has_stream_data.self) == NULL \
    ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
    : ((sender)->on_has_stream_data.cb((sender)->on_has_stream_data.self, (sid))))
#define GQUIC_SENDER_ON_STREAM_COMPLETED(sender, sid) \
    (((sender)->on_stream_completed.self) == NULL \
    ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
    : ((sender)->on_stream_completed.cb((sender)->on_stream_completed.self, (sid))))

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

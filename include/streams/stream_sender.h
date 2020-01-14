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

#define GQUIC_SENDER_QUEUE_CTRL_FRAME(sender, frame) \
    (((sender)->self) == NULL \
     ? -1 \
     : ((sender)->queue_ctrl_frame((sender)->self, (frame))))
#define GQUIC_SENDER_ON_HAS_STREAM_DATA(sender, sid) \
    (((sender)->self) == NULL \
    ? -1 \
    : ((sender)->on_has_stream_data((sender)->self, (sid))))
#define GQUIC_SENDER_ON_STREAM_COMPLETED(sender, sid) \
    (((sender)->self) == NULL \
    ? -1 \
    : ((sender)->on_stream_completed((sender)->self, (sid))))

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

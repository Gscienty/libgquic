#ifndef _LIBGQUIC_FRAME_STREAM_H
#define _LIBGQUIC_FRAME_STREAM_H

#include "frame/meta.h"
#include "streams/type.h"
#include "util/str.h"
#include "exception.h"

typedef struct gquic_frame_stream_s gquic_frame_stream_t;
struct gquic_frame_stream_s {
    u_int64_t id;
    u_int64_t off;
    gquic_str_t data;
};

gquic_frame_stream_t *gquic_frame_stream_alloc();
u_int64_t gquic_frame_stream_data_capacity(const u_int64_t size, const gquic_frame_stream_t *const frame);
int gquic_frame_stream_split(gquic_frame_stream_t **new_frame, gquic_frame_stream_t *const frame, const u_int64_t size);

static inline int gquic_frame_stream_set_fin(gquic_frame_stream_t *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_FRAME_META(frame).type |= 0x01;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline int gquic_frame_stream_get_fin(gquic_frame_stream_t *const frame) {
    if (frame == NULL) {
        return 1;
    }

    return (GQUIC_FRAME_META(frame).type & 0x01) != 0x00;
}

#endif

#include "frame/reset_stream.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_reset_stream_size(const void *const);
static int gquic_frame_reset_stream_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_reset_stream_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_reset_stream_init(void *const);
static int gquic_frame_reset_stream_dtor(void *const);

gquic_frame_reset_stream_t *gquic_frame_reset_stream_alloc() {
    gquic_frame_reset_stream_t *frame = gquic_frame_alloc(sizeof(gquic_frame_reset_stream_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x04;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_reset_stream_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_reset_stream_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_reset_stream_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_reset_stream_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_reset_stream_size;

    return frame;
}

static size_t gquic_frame_reset_stream_size(const void *const frame) {
    const gquic_frame_reset_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->errcode) + gquic_varint_size(&spec->final_size) + gquic_varint_size(&spec->id);
}

static int gquic_frame_reset_stream_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    const gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL || writer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    for (i = 0; i < 3; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }

    return GQUIC_SUCCESS;
}

static int gquic_frame_reset_stream_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(frame).type) {
        return GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED;
    }
    u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    int i;
    for (i = 0; i < 3; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }

    return GQUIC_SUCCESS;
}

static int gquic_frame_reset_stream_init(void *const frame) {
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    spec->errcode = 0;
    spec->final_size = 0;
    spec->id = 0;

    return GQUIC_SUCCESS;
}

static int gquic_frame_reset_stream_dtor(void *const frame) {
    if (frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    return GQUIC_SUCCESS;
}

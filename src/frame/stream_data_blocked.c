#include "frame/stream_data_blocked.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_stream_data_blocked_size(const void *const);
static int gquic_frame_stream_data_blocked_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_stream_data_blocked_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_stream_data_blocked_init(void *const);
static int gquic_frame_stream_data_blocked_dtor(void *const);

gquic_frame_stream_data_blocked_t *gquic_frame_stream_data_blocked_alloc() {
    gquic_frame_stream_data_blocked_t *frame = gquic_frame_alloc(sizeof(gquic_frame_stream_data_blocked_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x15;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_stream_data_blocked_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_stream_data_blocked_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_stream_data_blocked_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_stream_data_blocked_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_stream_data_blocked_size;

    return frame;
}

static size_t gquic_frame_stream_data_blocked_size(const void *const frame) {
    const gquic_frame_stream_data_blocked_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&spec->limit);
}

static int gquic_frame_stream_data_blocked_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    const gquic_frame_stream_data_blocked_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->id, &spec->limit };
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_data_blocked_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_stream_data_blocked_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    u_int64_t *vars[] = { &spec->id, &spec->limit };
    int i = 0;
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_data_blocked_init(void *const frame) {
    gquic_frame_stream_data_blocked_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->id = 0;
    spec->limit = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stream_data_blocked_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

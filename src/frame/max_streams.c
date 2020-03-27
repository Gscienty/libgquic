#include "frame/max_streams.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_max_streams_size(const void *const);
static int gquic_frame_max_streams_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_max_streams_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_max_streams_init(void *const);
static int gquic_frame_max_streams_dtor(void *const);

gquic_frame_max_streams_t *gquic_frame_max_streams_alloc() {
    gquic_frame_max_streams_t *frame = gquic_frame_alloc(sizeof(gquic_frame_max_streams_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_max_streams_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_max_streams_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_max_streams_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_max_streams_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_max_streams_size;

    return frame;
}

static size_t gquic_frame_max_streams_size(const void *const frame) {
    const gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->max);
}

static int gquic_frame_max_streams_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->max, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_max_streams_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_max_streams_t *spec = frame;
    u_int8_t type;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x12 && type != 0x13) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    GQUIC_FRAME_META(spec).type = type;
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->max, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_max_streams_init(void *const frame) {
    gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->max = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_max_streams_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


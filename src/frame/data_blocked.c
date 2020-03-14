#include "frame/data_blocked.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_data_blocked_size(const void *const);
static int gquic_frame_data_blocked_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_data_blocked_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_data_blocked_init(void *const);
static int gquic_frame_data_blocked_dtor(void *const);

gquic_frame_data_blocked_t *gquic_frame_data_blocked_alloc() {
    gquic_frame_data_blocked_t *frame = gquic_frame_alloc(sizeof(gquic_frame_data_blocked_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x14;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_data_blocked_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_data_blocked_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_data_blocked_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_data_blocked_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_data_blocked_size;
    return frame;
}

static size_t gquic_frame_data_blocked_size(const void *const frame) {
    const gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->limit);
}

static int gquic_frame_data_blocked_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->limit, writer));

    return GQUIC_SUCCESS;
}

static int gquic_frame_data_blocked_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->limit, reader));

    return GQUIC_SUCCESS;
}

static int gquic_frame_data_blocked_init(void *const frame) {
    gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    spec->limit = 0;

    return GQUIC_SUCCESS;
}

static int gquic_frame_data_blocked_dtor(void *const frame) {
    if (frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    return GQUIC_SUCCESS;
}

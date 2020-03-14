#include "frame/path_response.h"
#include "frame/meta.h"
#include "exception.h"
#include <string.h>

static size_t gquic_frame_path_response_size(const void *const);
static int gquic_frame_path_response_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_path_response_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_path_response_init(void *const);
static int gquic_frame_path_response_dtor(void *const);

gquic_frame_path_response_t *gquic_frame_path_response_alloc() {
    gquic_frame_path_response_t *frame = gquic_frame_alloc(sizeof(gquic_frame_path_response_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x1b;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_path_response_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_path_response_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_path_response_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_path_response_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_path_response_size;

    return frame;
}

static size_t gquic_frame_path_response_size(const void *const frame) {
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + 8;
}

static int gquic_frame_path_response_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    gquic_str_t data = { 8, (void *) spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &data));

    return GQUIC_SUCCESS;
}

static int gquic_frame_path_response_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_path_response_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(reader)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED;
    }
    gquic_str_t data = { 8, spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&data, reader));

    return GQUIC_SUCCESS;
}

static int gquic_frame_path_response_init(void *const frame) {
    (void) frame;
    return GQUIC_SUCCESS;
}

static int gquic_frame_path_response_dtor(void *const frame) {
    if (frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    return GQUIC_SUCCESS;
}


#include "frame/stop_sending.h"
#include "frame/meta.h"
#include "exception.h"
#include <stddef.h>

static size_t gquic_frame_stop_sending_size(const void *const);
static int gquic_frame_stop_sending_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_stop_sending_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_stop_sending_init(void *const);
static int gquic_frame_stop_sending_dtor(void *const);

gquic_frame_stop_sending_t *gquic_frame_stop_sending_alloc() {
    gquic_frame_stop_sending_t *frame = gquic_frame_alloc(sizeof(gquic_frame_stop_sending_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x05;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_stop_sending_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_stop_sending_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_stop_sending_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_stop_sending_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_stop_sending_size;

    return frame;
}

static size_t gquic_frame_stop_sending_size(const void *const frame) {
    const gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&spec->errcode);
}

static int gquic_frame_stop_sending_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    const gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->id, &spec->errcode };
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer) != 0);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stop_sending_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_stop_sending_t *spec = frame;
    if (frame == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(frame).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    u_int64_t *vars[] = { &spec->id, &spec->errcode };
    int i;
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stop_sending_init(void *const frame) {
    gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->errcode = 0;
    spec->id = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_stop_sending_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


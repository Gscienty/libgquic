#include "frame/reset_stream.h"
#include "frame/meta.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

static size_t gquic_frame_reset_stream_size(const void *const);
static int gquic_frame_reset_stream_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_reset_stream_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_reset_stream_init(void *const);
static int gquic_frame_reset_stream_dtor(void *const);

int gquic_frame_reset_stream_alloc(gquic_frame_reset_stream_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_reset_stream_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x04;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_reset_stream_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_reset_stream_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_reset_stream_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_reset_stream_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_reset_stream_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    for (i = 0; i < 3; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_reset_stream_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(frame).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize RESET_STREAM frame");

    u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    int i;
    for (i = 0; i < 3; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_reset_stream_init(void *const frame) {
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->errcode = 0;
    spec->final_size = 0;
    spec->id = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_reset_stream_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

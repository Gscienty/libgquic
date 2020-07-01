#include "frame/connection_close.h"
#include "frame/meta.h"
#include "util/malloc.h"
#include "exception.h"
#include "log.h"
#include <string.h>

static size_t gquic_frame_connection_close_size(const void *const);
static int gquic_frame_connection_close_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_connection_close_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_connection_close_init(void *const);
static int gquic_frame_connection_close_dtor(void *const);

int gquic_frame_connection_close_alloc(gquic_frame_connection_close_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_connection_close_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x00;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_connection_close_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_connection_close_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_connection_close_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_connection_close_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_connection_close_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_connection_close_size(const void *const frame) {
    const gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->errcode)
        + (GQUIC_FRAME_META(spec).type == 0x1d ? gquic_varint_size(&spec->type) : 0)
        + gquic_varint_size(&spec->phase_len)
        + spec->phase_len;
}

static int gquic_frame_connection_close_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));

    const u_int64_t *vars[] = { &spec->errcode, (GQUIC_FRAME_META(spec).type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    int i;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }
    gquic_str_t phase = { spec->phase_len, spec->phase };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &phase));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_connection_close_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    u_int8_t type;
    int i = 0;
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x1c && type != 0x1d) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize CONNECTION_CLOSE frame");

    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = { &spec->errcode, (type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &spec->phase, spec->phase_len));
    gquic_str_t phase = { spec->phase_len, spec->phase };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&phase, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_connection_close_init(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->errcode = 0;
    spec->phase_len = 0;
    spec->type = 0;
    spec->phase = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_connection_close_dtor(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (spec->phase != NULL) {
        gquic_free(spec->phase);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#include "frame/connection_close.h"
#include "frame/meta.h"
#include <string.h>
#include <malloc.h>

static size_t gquic_frame_connection_close_size(const void *const);
static int gquic_frame_connection_close_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_connection_close_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_connection_close_init(void *const);
static int gquic_frame_connection_close_dtor(void *const);

gquic_frame_connection_close_t *gquic_frame_connection_close_alloc() {
    gquic_frame_connection_close_t *frame = gquic_frame_alloc(sizeof(gquic_frame_connection_close_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_connection_close_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_connection_close_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_connection_close_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_connection_close_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_connection_close_size;
    return frame;
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
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }

    const u_int64_t *vars[] = { &spec->errcode, (GQUIC_FRAME_META(spec).type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    int i;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        if (gquic_varint_serialize(vars[i], writer) != 0) {
            return -4;
        }
    }
    gquic_str_t phase = { spec->phase_len, spec->phase };
    if (gquic_writer_str_write(writer, &phase) != 0) {
        return -5;
    }
    return 0;
}

static int gquic_frame_connection_close_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    u_int8_t type;
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x1c && type != 0x1d) {
        return -2;
    }
    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = { &spec->errcode, (type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    int i = 0;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        if (gquic_varint_deserialize(vars[i], reader) != 0) {
            return -3;
        }
    }
    spec->phase = malloc(spec->phase_len);
    if (spec->phase == NULL) {
        return -4;
    }
    gquic_str_t phase = { spec->phase_len, spec->phase };
    if (gquic_reader_str_read(&phase, reader) != 0) {
        return -5;
    }
    return 0;
}

static int gquic_frame_connection_close_init(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->errcode = 0;
    spec->phase_len = 0;
    spec->type = 0;
    spec->phase = NULL;
    return 0;
}

static int gquic_frame_connection_close_dtor(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (spec->phase != NULL) {
        free(spec->phase);
    }
    return 0;
}

#include "frame/streams_blocked.h"
#include "frame/meta.h"
#include <stddef.h>

static size_t gquic_frame_streams_blocked_size(const void *const);
static int gquic_frame_streams_blocked_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_streams_blocked_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_streams_blocked_init(void *const);
static int gquic_frame_streams_blocked_dtor(void *const);

gquic_frame_streams_blocked_t *gquic_frame_streams_blocked_alloc() {
    gquic_frame_streams_blocked_t *frame = gquic_frame_alloc(sizeof(gquic_frame_streams_blocked_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_streams_blocked_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_streams_blocked_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_streams_blocked_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_streams_blocked_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_streams_blocked_size;
    return frame;
}

static size_t gquic_frame_streams_blocked_size(const void *const frame) {
    const gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->limit);
}

static int gquic_frame_streams_blocked_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }
    if (gquic_varint_serialize(&spec->limit, writer) != 0) {
        return -4;
    }
    return 0;
}

static int gquic_frame_streams_blocked_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_streams_blocked_t *spec = frame;
    u_int8_t type;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x16 && type != 0x17) {
        return -2;
    }
    GQUIC_FRAME_META(spec).type = type;
    if (gquic_varint_deserialize(&spec->limit, reader) != 0) {
        return -3;
    }
    return 0;
}

static int gquic_frame_streams_blocked_init(void *const frame) {
    gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->limit = 0;
    return 0;
}

static int gquic_frame_streams_blocked_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}


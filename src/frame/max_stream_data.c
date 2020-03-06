#include "frame/max_stream_data.h"
#include "frame/meta.h"
#include <stddef.h>

static size_t gquic_frame_max_stream_data_size(const void *const);
static int gquic_frame_max_stream_data_serialize(const void *const, gquic_writer_str_t *const);
static int gquic_frame_max_stream_data_deserialize(void *const, gquic_reader_str_t *const);
static int gquic_frame_max_stream_data_init(void *const);
static int gquic_frame_max_stream_data_dtor(void *const);

gquic_frame_max_stream_data_t *gquic_frame_max_stream_data_alloc() {
    gquic_frame_max_stream_data_t *frame = gquic_frame_alloc(sizeof(gquic_frame_max_stream_data_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x11;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_max_stream_data_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_max_stream_data_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_max_stream_data_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_max_stream_data_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_max_stream_data_size;
    return frame;
}

static size_t gquic_frame_max_stream_data_size(const void *const frame) {
    const gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&spec->max);
}

static int gquic_frame_max_stream_data_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        return -1;
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type) != 0) {
        return -3;
    }
    const u_int64_t *vars[] = { &spec->id, &spec->max };
    int i = 0;
    for (i = 0; i < 2; i++) {
        if (gquic_varint_serialize(vars[i], writer) != 0) {
            return -4;
        }
    }
    return 0;
}

static int gquic_frame_max_stream_data_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        return -2;
    }
    u_int64_t *vars[] = { &spec->id, &spec->max };
    int i = 0;
    for (i = 0; i < 2; i++) {
        if (gquic_varint_deserialize(vars[i], reader) != 0) {
            return -3;
        }
    }
    return 0;
}

static int gquic_frame_max_stream_data_init(void *const frame) {
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->id = 0;
    spec->max = 0;
    return 0;
}

static int gquic_frame_max_stream_data_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

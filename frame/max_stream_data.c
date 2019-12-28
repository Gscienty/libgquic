#include "frame/max_stream_data.h"
#include "frame/meta.h"
#include <stddef.h>

static size_t gquic_frame_max_stream_data_size(const void *const);
static ssize_t gquic_frame_max_stream_data_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_max_stream_data_deserialize(void *const, const void *, const size_t);
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

static ssize_t gquic_frame_max_stream_data_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_SIZE(spec) > size) {
        return -3;
    }
    ((u_int8_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    const u_int64_t *vars[] = { &spec->id, &spec->max };
    int i = 0;
    for (i = 0; i < 2; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    return off;
}

static ssize_t gquic_frame_max_stream_data_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((u_int8_t *) buf)[off++]) {
        return -3;
    }
    u_int64_t *vars[] = { &spec->id, &spec->max };
    int i = 0;
    for (i = 0; i < 2; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    return off;
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

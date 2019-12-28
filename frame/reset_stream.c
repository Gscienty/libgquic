#include "frame/reset_stream.h"
#include "frame/meta.h"
#include <malloc.h>

static size_t gquic_frame_reset_stream_size(const void *const);
static ssize_t gquic_frame_reset_stream_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_reset_stream_deserialize(void *const, const void *, const size_t);
static int gquic_frame_reset_stream_init(void *const);
static int gquic_frame_reset_stream_release(void *const);

gquic_frame_reset_stream_t *gquic_frame_reset_stream_alloc() {
    gquic_frame_reset_stream_t *frame = gquic_frame_alloc(sizeof(gquic_frame_reset_stream_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x04;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_reset_stream_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_reset_stream_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_reset_stream_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_reset_stream_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_reset_stream_size;
    return frame;
}

static size_t gquic_frame_reset_stream_size(const void *const frame) {
    const gquic_frame_reset_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->errcode) + gquic_varint_size(&spec->final_size) + gquic_varint_size(&spec->id);
}

static ssize_t gquic_frame_reset_stream_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_SIZE(spec) > size) {
        return -3;
    }
    ((u_int8_t *) buf)[off++] = GQUIC_FRAME_META(frame).type;
    const u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    int i;
    for (i = 0; i < 3; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    return off;
}

static ssize_t gquic_frame_reset_stream_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (((u_int8_t *) buf)[off++] != GQUIC_FRAME_META(frame).type) {
        return -3;
    }
    u_int64_t *vars[] = { &spec->id, &spec->errcode, &spec->final_size };
    int i;
    for (i = 0; i < 3; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    return off;
}

static int gquic_frame_reset_stream_init(void *const frame) {
    gquic_frame_reset_stream_t *spec = frame;
    if (frame == NULL) {
        return -1;
    }
    spec->errcode = 0;
    spec->final_size = 0;
    spec->id = 0;
    return 0;
}

static int gquic_frame_reset_stream_release(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

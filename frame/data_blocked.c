#include "frame/data_blocked.h"
#include "frame/meta.h"
#include <stddef.h>

static size_t gquic_frame_data_blocked_size(const void *const);
static ssize_t gquic_frame_data_blocked_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_data_blocked_deserialize(void *const, const void *, const size_t);
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

static ssize_t gquic_frame_data_blocked_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_data_blocked_t *spec = frame;
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
    serialize_len = gquic_varint_serialize(&spec->limit, buf + off, size - off);
    if (serialize_len <= 0) {
        return -3;
    }
    return off;
}

static ssize_t gquic_frame_data_blocked_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((u_int8_t *) buf)[off++]) {
        return -3;
    }
    deserialize_len = gquic_varint_deserialize(&spec->limit, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -4;
    }
    return off;
}

static int gquic_frame_data_blocked_init(void *const frame) {
    gquic_frame_data_blocked_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->limit = 0;
    return 0;
}

static int gquic_frame_data_blocked_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

#include "frame/streams_blocked.h"
#include "frame/meta.h"

static size_t gquic_frame_streams_blocked_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_streams_blocked_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_streams_blocked_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_streams_blocked_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_streams_blocked_release(gquic_abstract_frame_ptr_t);

gquic_frame_streams_blocked_t *gquic_frame_streams_blocked_alloc() {
    gquic_frame_streams_blocked_t *frame = gquic_frame_alloc(sizeof(gquic_frame_streams_blocked_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_streams_blocked_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_streams_blocked_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_streams_blocked_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_streams_blocked_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_streams_blocked_size;
    return frame;
}

static size_t gquic_frame_streams_blocked_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + spec->limit.length;
}

static ssize_t gquic_frame_streams_blocked_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_frame_size(spec) > size) {
        return -3;
    }
    ((gquic_frame_type_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    serialize_len = gquic_varint_serialize(&spec->limit, buf + off, size - off);
    if (serialize_len <= 0) {
        return -3;
    }
    return off;
}

static ssize_t gquic_frame_streams_blocked_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_streams_blocked_t *spec = frame;
    gquic_frame_type_t type;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((gquic_frame_type_t *) buf)[off++];
    if (type != 0x16 && type != 0x17) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    deserialize_len = gquic_varint_deserialize(&spec->limit, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -4;
    }
    return off;
}

static int gquic_frame_streams_blocked_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->limit, 0);
    return 0;
}

static int gquic_frame_streams_blocked_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}


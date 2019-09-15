#include "frame/max_streams.h"
#include "frame/meta.h"

static size_t gquic_frame_max_streams_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_max_streams_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_max_streams_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_max_streams_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_max_streams_release(gquic_abstract_frame_ptr_t);

gquic_frame_max_streams_t *gquic_frame_max_streams_alloc() {
    gquic_frame_max_streams_t *frame = gquic_frame_alloc(sizeof(gquic_frame_max_streams_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_max_streams_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_max_streams_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_max_streams_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_max_streams_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_max_streams_size;
    return frame;
}

static size_t gquic_frame_max_streams_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + spec->max.length;
}

static ssize_t gquic_frame_max_streams_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    ((gquic_frame_type_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    serialize_len = gquic_varint_serialize(&spec->max, buf + off, size - off);
    if (serialize_len <= 0) {
        return -3;
    }
    return off;
}

static ssize_t gquic_frame_max_streams_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_max_streams_t *spec = frame;
    gquic_frame_type_t type;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((gquic_frame_type_t *) buf)[off++];
    if (type == 0x12 || type == 0x13) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    deserialize_len = gquic_varint_deserialize(&spec->max, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -4;
    }
    return off;
}

static int gquic_frame_max_streams_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_max_streams_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->max, 0);
    return 0;
}

static int gquic_frame_max_streams_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    gquic_frame_release(frame);
    return 0;
}


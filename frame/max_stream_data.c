#include "frame/max_stream_data.h"
#include "frame/meta.h"

static size_t gquic_frame_max_stream_data_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_max_stream_data_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_max_stream_data_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_max_stream_data_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_max_stream_data_release(gquic_abstract_frame_ptr_t);

gquic_frame_max_stream_data_t *gquic_frame_max_stream_data_alloc() {
    gquic_frame_max_stream_data_t *frame = gquic_frame_alloc(sizeof(gquic_frame_max_stream_data_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x11;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_max_stream_data_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_max_stream_data_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_max_stream_data_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_max_stream_data_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_max_stream_data_size;
    return frame;
}

static size_t gquic_frame_max_stream_data_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + spec->id.length + spec->max.length;
}

static ssize_t gquic_frame_max_stream_data_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_max_stream_data_t *spec = frame;
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
    gquic_varint_t *vars[] = { &spec->id, &spec->max };
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

static ssize_t gquic_frame_max_stream_data_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((gquic_frame_type_t *) buf)[off++]) {
        return -3;
    }
    gquic_varint_t *vars[] = { &spec->id, &spec->max };
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

static int gquic_frame_max_stream_data_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_max_stream_data_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->id, 0);
    gquic_varint_wrap(&spec->max, 0);
    return 0;
}

static int gquic_frame_max_stream_data_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

#include "frame/retire_connection_id.h"
#include "frame/meta.h"

static size_t gquic_frame_retire_connection_id_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_retire_connection_id_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_retire_connection_id_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_retire_connection_id_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_retire_connection_id_release(gquic_abstract_frame_ptr_t);

gquic_frame_retire_connection_id_t *gquic_frame_retire_connection_id_alloc() {
    gquic_frame_retire_connection_id_t *frame = gquic_frame_alloc(sizeof(gquic_frame_retire_connection_id_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x19;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_retire_connection_id_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_retire_connection_id_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_retire_connection_id_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_retire_connection_id_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_retire_connection_id_size;
    return frame;
}

static size_t gquic_frame_retire_connection_id_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_retire_connection_id_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + spec->seq.length;
}

static ssize_t gquic_frame_retire_connection_id_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_retire_connection_id_t *spec = frame;
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
    serialize_len = gquic_varint_serialize(&spec->seq, buf + off, size - off);
    if (serialize_len <= 0) {
        return -3;
    }
    return off;
}

static ssize_t gquic_frame_retire_connection_id_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_retire_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((gquic_frame_type_t *) buf)[off++]) {
        return -3;
    }
    deserialize_len = gquic_varint_deserialize(&spec->seq, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -4;
    }
    return off;
}

static int gquic_frame_retire_connection_id_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_retire_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->seq, 0);
    return 0;
}

static int gquic_frame_retire_connection_id_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

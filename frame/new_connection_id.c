#include "frame/new_connection_id.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_new_connection_id_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_new_connection_id_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_new_connection_id_deserialize(gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_new_connection_id_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_new_connection_id_release(gquic_abstract_frame_ptr_t);

gquic_frame_new_connection_id_t *gquic_frame_new_connection_id_alloc() {
    gquic_frame_new_connection_id_t *frame = gquic_frame_alloc(sizeof(gquic_frame_new_connection_id_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x18;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_new_connection_id_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_new_connection_id_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_new_connection_id_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_new_connection_id_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_new_connection_id_size;
    return frame;
}

static size_t gquic_frame_new_connection_id_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + spec->seq.length + spec->prior.length + 1 + spec->len + 16;
}

static ssize_t gquic_frame_new_connection_id_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).size_func(spec) > size) {
        return -3;
    }
    ((gquic_frame_type_t *) buf)[off++] = GQUIC_FRAME_META(spec).type;
    gquic_util_varint_t *vars[2] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    spec->len = ((unsigned char *) (buf + (off++)))[0];
    memcpy(spec->conn_id, buf + off, spec->len);
    off += spec->len;
    memcpy(spec->token, buf + off, 16);
    return off + 16;
}

static ssize_t gquic_frame_new_connection_id_deserialize(gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf != NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((gquic_frame_type_t *) buf)[off++]) {
        return -3;
    }
    gquic_util_varint_t *vars[] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    memcpy(spec->conn_id, buf + off, spec->len);
    off += spec->len;
    memcpy(spec->token, buf + off, 16);
    return off + 16;
}

static int gquic_frame_new_connection_id_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->prior, 0);
    gquic_varint_wrap(&spec->seq, 0);
    spec->len = 0;
    return 0;
}

static int gquic_frame_new_connection_id_release(gquic_abstract_frame_ptr_t frame) {
    if (frame == NULL) {
        return -1;
    }
    gquic_frame_release(frame);
    return 0;
}

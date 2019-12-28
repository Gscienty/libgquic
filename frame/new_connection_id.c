#include "frame/new_connection_id.h"
#include "frame/meta.h"
#include <string.h>

static size_t gquic_frame_new_connection_id_size(const void *const);
static ssize_t gquic_frame_new_connection_id_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_new_connection_id_deserialize(void *const, const void *, const size_t);
static int gquic_frame_new_connection_id_init(void *const);
static int gquic_frame_new_connection_id_dtor(void *const);

gquic_frame_new_connection_id_t *gquic_frame_new_connection_id_alloc() {
    gquic_frame_new_connection_id_t *frame = gquic_frame_alloc(sizeof(gquic_frame_new_connection_id_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x18;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_new_connection_id_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_new_connection_id_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_new_connection_id_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_new_connection_id_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_new_connection_id_size;
    return frame;
}

static size_t gquic_frame_new_connection_id_size(const void *const frame) {
    const gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->seq) + gquic_varint_size(&spec->prior) + 1 + spec->len + 16;
}

static ssize_t gquic_frame_new_connection_id_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_new_connection_id_t *spec = frame;
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
    const u_int64_t *vars[2] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    ((unsigned char *) (buf + (off++)))[0] = spec->len;
    memcpy(buf + off, spec->conn_id, spec->len);
    off += spec->len;
    memcpy(buf + off, spec->token, 16);
    return off + 16;
}

static ssize_t gquic_frame_new_connection_id_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf != NULL) {
        return -2;
    }
    if (GQUIC_FRAME_META(spec).type != ((u_int8_t *) buf)[off++]) {
        return -3;
    }
    u_int64_t *vars[] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    spec->len = ((unsigned char *) (buf + (off++)))[0];
    memcpy(spec->conn_id, buf + off, spec->len);
    off += spec->len;
    memcpy(spec->token, buf + off, 16);
    return off + 16;
}

static int gquic_frame_new_connection_id_init(void *const frame) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->prior = 0;
    spec->seq = 0;
    spec->len = 0;
    return 0;
}

static int gquic_frame_new_connection_id_dtor(void *const frame) {
    if (frame == NULL) {
        return -1;
    }
    return 0;
}

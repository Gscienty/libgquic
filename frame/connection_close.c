#include "frame/connection_close.h"
#include "frame/meta.h"
#include <string.h>
#include <malloc.h>

static size_t gquic_frame_connection_close_size(const void *const);
static ssize_t gquic_frame_connection_close_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_connection_close_deserialize(void *const, const void *, const size_t);
static int gquic_frame_connection_close_init(void *const);
static int gquic_frame_connection_close_release(void *const);

gquic_frame_connection_close_t *gquic_frame_connection_close_alloc() {
    gquic_frame_connection_close_t *frame = gquic_frame_alloc(sizeof(gquic_frame_connection_close_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_connection_close_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_connection_close_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_connection_close_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_connection_close_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_connection_close_size;
    return frame;
}

static size_t gquic_frame_connection_close_size(const void *const frame) {
    const gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->errcode)
        + gquic_varint_size(&spec->phase_len)
        + (GQUIC_FRAME_META(spec).type == 0x1d ? gquic_varint_size(&spec->type) : 0)
        + gquic_varint_size(&spec->phase_len)
        + spec->phase_len;
}

static ssize_t gquic_frame_connection_close_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_connection_close_t *spec = frame;
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

    const u_int64_t *vars[] = { &spec->errcode, (GQUIC_FRAME_META(spec).type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    int i;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    memcpy(buf + off, spec->phase, spec->phase_len);
    return off + spec->phase_len;
}

static ssize_t gquic_frame_connection_close_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    u_int8_t type;
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((u_int8_t *) buf)[off++];
    if (type != 0x1c && type != 0x1d) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = { &spec->errcode, (type == 0x1d ? &spec->type : NULL), &spec->phase_len };
    int i = 0;
    for (i = 0; i < 3; i++) {
        if (vars[i] == NULL) {
            continue;
        }
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    spec->phase = malloc(spec->phase_len);
    if (spec->phase == NULL) {
        return -4;
    }
    memcpy(spec->phase, buf + off, spec->phase_len);
    return off + spec->phase_len;
}

static int gquic_frame_connection_close_init(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->errcode = 0;
    spec->phase_len = 0;
    spec->type = 0;
    spec->phase = NULL;
    return 0;
}

static int gquic_frame_connection_close_release(void *const frame) {
    gquic_frame_connection_close_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (spec->phase != NULL) {
        free(spec->phase);
    }
    return 0;
}

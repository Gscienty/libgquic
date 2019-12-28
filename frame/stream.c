#include "frame/stream.h"
#include "frame/meta.h"
#include <string.h>
#include <malloc.h>

static size_t gquic_frame_stream_size(const void *const);
static ssize_t gquic_frame_stream_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_stream_deserialize(void *const, const void *, const size_t);
static int gquic_frame_stream_init(void *const);
static int gquic_frame_stream_release(void *const);

gquic_frame_stream_t *gquic_frame_stream_alloc() {
    gquic_frame_stream_t *frame = gquic_frame_alloc(sizeof(gquic_frame_stream_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_stream_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_stream_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_stream_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_stream_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_stream_size;
    return frame;
}

static size_t gquic_frame_stream_size(const void *const frame) {
    const gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&spec->len) + gquic_varint_size(&spec->off) + spec->len;
}

static ssize_t gquic_frame_stream_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_stream_t *spec = frame;
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
    const u_int64_t *vars[] = {
        &spec->id,
        ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? &spec->off : NULL),
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &spec->len : NULL)
    };
    int i = 0;
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
    memcpy(buf + off, spec->data, spec->len);
    return off + spec->len;
}

static ssize_t gquic_frame_stream_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    u_int8_t type;
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((u_int8_t *) buf)[off++];
    if ((type & 0x08) != 0x08) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = {
        &spec->id,
        ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? &spec->off : NULL),
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &spec->len : NULL)
    };
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
    spec->data = malloc(spec->len);
    if (spec->data == NULL) {
        return -4;
    }
    memcpy(spec->data, buf + off, spec->len);
    return off + spec->len;
}

static int gquic_frame_stream_init(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->data = NULL;
    spec->id = 0;
    spec->len = 0;
    spec->off = 0;
    return 0;
}

static int gquic_frame_stream_release(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (spec->data != NULL) {
        free(spec->data);
    }
    return 0;
}

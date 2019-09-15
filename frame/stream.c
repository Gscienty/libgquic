#include "frame/stream.h"
#include "frame/meta.h"
#include <string.h>
#include <malloc.h>

static size_t gquic_frame_stream_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_stream_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_stream_deserialize(const gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_stream_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_stream_release(gquic_abstract_frame_ptr_t);

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

static size_t gquic_frame_stream_size(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + spec->id.length + spec->len.length + spec->off.length + spec->len.value;
}

static ssize_t gquic_frame_stream_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_stream_t *spec = frame;
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
    gquic_util_varint_t *vars[] = {
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
    memcpy(buf + off, spec->data, spec->len.value);
    return off + spec->len.value;
}

static ssize_t gquic_frame_stream_deserialize(const gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_stream_type_t type;
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((gquic_frame_type_t *) buf)[off++];
    if ((type & 0x08) != 0x08) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    gquic_util_varint_t *vars[] = {
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
    spec->data = malloc(spec->len.value);
    if (spec->data == NULL) {
        return -4;
    }
    memcpy(spec->data, buf + off, spec->len.value);
    return off + spec->len.value;
}

static int gquic_frame_stream_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->data = NULL;
    gquic_varint_wrap(&spec->id, 0);
    gquic_varint_wrap(&spec->len, 0);
    gquic_varint_wrap(&spec->off, 0);
    return 0;
}

static int gquic_frame_stream_release(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (spec->data != NULL) {
        free(spec->data);
    }
    gquic_frame_release(spec);
    return 0;
}

#include "frame/stream.h"
#include "frame/meta.h"
#include <string.h>
#include <malloc.h>
#include "frame/stream_pool.h"

static size_t gquic_frame_stream_size(const void *const);
static ssize_t gquic_frame_stream_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_stream_deserialize(void *const, const void *, const size_t);
static int gquic_frame_stream_init(void *const);
static int gquic_frame_stream_dtor(void *const);

gquic_frame_stream_t *gquic_frame_stream_alloc() {
    gquic_frame_stream_t *frame = gquic_frame_alloc(sizeof(gquic_frame_stream_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_stream_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_stream_init;
    GQUIC_FRAME_META(frame).dtor_func = gquic_frame_stream_dtor;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_stream_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_stream_size;
    return frame;
}

static size_t gquic_frame_stream_size(const void *const frame) {
    u_int64_t len = 0;
    const gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    len = GQUIC_STR_SIZE(&spec->data);
    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&len) + gquic_varint_size(&spec->off) + len;
}

static ssize_t gquic_frame_stream_serialize(const void *const frame, void *buf, const size_t size) {
    u_int64_t len = 0;
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
    len = GQUIC_STR_SIZE(&spec->data);
    const u_int64_t *vars[] = {
        &spec->id,
        ((GQUIC_FRAME_META(spec).type & 0x04) == 0x04 ? &spec->off : NULL),
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &len : NULL)
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
    memcpy(buf + off, GQUIC_STR_VAL(&spec->data), GQUIC_STR_SIZE(&spec->data));
    return off + GQUIC_STR_SIZE(&spec->data);
}

static ssize_t gquic_frame_stream_deserialize(void *const frame, const void *buf, const size_t size) {
    u_int64_t len = 0;
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
        ((GQUIC_FRAME_META(spec).type & 0x02) == 0x02 ? &len: NULL)
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
    if (gquic_str_alloc(&spec->data, len) != 0) {
        return -4;
    }
    memcpy(GQUIC_STR_VAL(&spec->data), buf + off, len);
    return off + len;
}

static int gquic_frame_stream_init(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_str_init(&spec->data);
    spec->id = 0;
    spec->off = 0;
    return 0;
}

static int gquic_frame_stream_dtor(void *const frame) {
    gquic_frame_stream_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_str_reset(&spec->data);
    return 0;
}

u_int64_t gquic_frame_stream_data_capacity(const u_int64_t size, const gquic_frame_stream_t *const frame) {
    u_int64_t header_len = 0;
    u_int64_t data_len = 0;
    u_int64_t capacity_size = 0;
    if (frame == NULL) {
        return 0;
    }
    data_len = GQUIC_STR_SIZE(&frame->data);
    header_len = 1
        + gquic_varint_size(&frame->id)
        + ((GQUIC_FRAME_META(frame).type & 0x04) != 0x00 ? gquic_varint_size(&frame->off) : 0)
        + ((GQUIC_FRAME_META(frame).type & 0x02) != 0x00 ? gquic_varint_size(&data_len) : 0);
    if (header_len > size) {
        return 0;
    }
    capacity_size = size - header_len;
    if ((GQUIC_FRAME_META(frame).type & 0x02) != 0x00 && gquic_varint_size(&capacity_size) != 1) {
        capacity_size--;
    }
    return capacity_size;
}

int gquic_frame_stream_split(gquic_frame_stream_t **new_frame, gquic_frame_stream_t *const frame, const u_int64_t size) {
    u_int64_t capacity_size = 0;
    if (new_frame == NULL || frame == NULL) {
        return 0;
    }
    if (size > GQUIC_FRAME_SIZE(frame)) {
        return 0;
    }
    capacity_size = gquic_frame_stream_data_capacity(size, frame);
    if (capacity_size == 0) {
        *new_frame = NULL;
        return 1;
    }
    gquic_stream_frame_pool_get(new_frame);
    (*new_frame)->id = frame->id;
    (*new_frame)->off = frame->off;
    if (frame->off != 0) {
        GQUIC_FRAME_META(*new_frame).type |= 0x04;
    }
    GQUIC_FRAME_META(*new_frame).type |= 0x02;
    (*new_frame)->data = frame->data;
    frame->data.size = 0;
    frame->data.val = NULL;
    if (gquic_str_alloc(&frame->data, GQUIC_STR_SIZE(&(*new_frame)->data) - capacity_size) != 0) {
        return 0;
    }
    memcpy(GQUIC_STR_VAL(&frame->data), GQUIC_STR_VAL(&(*new_frame)->data) + capacity_size, GQUIC_STR_SIZE(&frame->data));
    (*new_frame)->data.size = capacity_size;
    frame->off += capacity_size;
    GQUIC_FRAME_META(frame).type |= 0x04;

    return 1;
}

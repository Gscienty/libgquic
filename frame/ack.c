#include "frame/ack.h"
#include "frame/meta.h"
#include "util/list.h"

static size_t gquic_frame_ack_size(gquic_abstract_frame_ptr_t);
static ssize_t gquic_frame_ack_serialize(const gquic_abstract_frame_ptr_t, void *, const size_t);
static ssize_t gquic_frame_ack_deserialize(const gquic_abstract_frame_ptr_t, const void *, const size_t);
static int gquic_frame_ack_init(gquic_abstract_frame_ptr_t);
static int gquic_frame_ack_release(gquic_abstract_frame_ptr_t);

gquic_frame_ack_t *gquic_frame_ack_alloc() {
    gquic_frame_ack_t *frame = gquic_frame_alloc(sizeof(gquic_frame_ack_t));
    if (frame == NULL) {
        return NULL;
    }
    GQUIC_FRAME_META(frame).type = 0x00;
    GQUIC_FRAME_META(frame).deserialize_func = gquic_frame_ack_deserialize;
    GQUIC_FRAME_META(frame).init_func = gquic_frame_ack_init;
    GQUIC_FRAME_META(frame).release_func = gquic_frame_ack_release;
    GQUIC_FRAME_META(frame).serialize_func = gquic_frame_ack_serialize;
    GQUIC_FRAME_META(frame).size_func = gquic_frame_ack_size;
    return frame;
}

static size_t gquic_frame_ack_size(gquic_abstract_frame_ptr_t frame) {
    size_t ret = 0;
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    ret = 1 + spec->largest_ack.length + spec->delay.length + spec->count.length + spec->first_range.length;
    gquic_frame_range_t *range;
    GQUIC_LIST_FOREACH(range, &spec->range) {
        ret += range->gap.length + range->range.length;
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        ret += spec->ecn.ect[0].length + spec->ecn.ect[1].length + spec->ecn.ecn_ce.length;
    }
    return ret;
}

static ssize_t gquic_frame_ack_serialize(const gquic_abstract_frame_ptr_t frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    gquic_frame_ack_t *spec = frame;
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
    gquic_varint_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    int i = 0;
    for (i = 0; i < 4; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    gquic_frame_range_t *range;
    GQUIC_LIST_FOREACH(range, &spec->range) {
        gquic_varint_t *vars[] = { &range->gap, &range->range };
        for (i = 0; i < 2; i++) {
            serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
            if (serialize_len <= 0) {
                return -4;
            }
            off += serialize_len;
        }
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        gquic_varint_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
        for (i = 0; i < 3; i++) {
            serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
            if (serialize_len <= 0) {
                return -4;
            }
            off += serialize_len;
        }
    }
    return off;
}

static ssize_t gquic_frame_ack_deserialize(const gquic_abstract_frame_ptr_t frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    gquic_frame_type_t type;
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((gquic_frame_type_t *) buf)[off++];
    if (type != 0x02 && type != 0x03) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    gquic_varint_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    size_t i = 0;
    for (i = 0; i < 4; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    for (i = 0; i < spec->count.value; i++) {
        if (gquic_list_insert_before(&spec->range, gquic_list_alloc(sizeof(gquic_frame_range_t))) != 0) {
            return -4;
        }
        gquic_frame_range_t *range = gquic_list_prev(GQUIC_LIST_PAYLOAD(&spec->range));
        gquic_varint_t *vars[] = { &range->gap, &range->range };
        int j = 0;
        for (j = 0; j < 2; j++) {
            deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
            if (deserialize_len <= 0) {
                return -4;
            }
            off += deserialize_len;
        }
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        gquic_varint_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
        for (i = 0; i < 3; i++) {
            deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
            if (deserialize_len <= 0) {
                return -4;
            }
            off += deserialize_len;
        }
    }
    return off;
}

static int gquic_frame_ack_init(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    gquic_varint_wrap(&spec->count, 0);
    gquic_varint_wrap(&spec->delay, 0);
    gquic_varint_wrap(&spec->ecn.ecn_ce, 0);
    gquic_varint_wrap(&spec->ecn.ect[0], 0);
    gquic_varint_wrap(&spec->ecn.ect[1], 0);
    gquic_varint_wrap(&spec->first_range, 0);
    gquic_varint_wrap(&spec->largest_ack, 0);
    gquic_list_head_init(&spec->range);
    return 0;
}

static int gquic_frame_ack_release(gquic_abstract_frame_ptr_t frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    while (gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->range)) != GQUIC_LIST_PAYLOAD(&spec->range)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->range)));
    }
    gquic_frame_release(spec);
    return 0;
}


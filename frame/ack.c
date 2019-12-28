#include "frame/ack.h"
#include "frame/meta.h"
#include "util/list.h"

static size_t gquic_frame_ack_size(const void *const);
static ssize_t gquic_frame_ack_serialize(const void *const, void *, const size_t);
static ssize_t gquic_frame_ack_deserialize(void *const, const void *, const size_t);
static int gquic_frame_ack_init(void *const);
static int gquic_frame_ack_release(void *const);

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

static size_t gquic_frame_ack_size(const void *const frame) {
    size_t ret = 0;
    const gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    ret = 1 + gquic_varint_size(&spec->largest_ack) + gquic_varint_size(&spec->delay) + gquic_varint_size(&spec->count) + gquic_varint_size(&spec->first_range);
    gquic_frame_ack_range_t *range;
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        ret += gquic_varint_size(&range->gap) + gquic_varint_size(&range->range);
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        ret += gquic_varint_size(&spec->ecn.ect[0]) + gquic_varint_size(&spec->ecn.ect[1]) + gquic_varint_size(&spec->ecn.ecn_ce);
    }
    return ret;
}

static ssize_t gquic_frame_ack_serialize(const void *const frame, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    const gquic_frame_ack_t *spec = frame;
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
    const u_int64_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    int i = 0;
    for (i = 0; i < 4; i++) {
        serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
        if (serialize_len <= 0) {
            return -4;
        }
        off += serialize_len;
    }
    gquic_frame_ack_range_t *range;
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        u_int64_t *vars[] = { &range->gap, &range->range };
        for (i = 0; i < 2; i++) {
            serialize_len = gquic_varint_serialize(vars[i], buf + off, size - off);
            if (serialize_len <= 0) {
                return -4;
            }
            off += serialize_len;
        }
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        const u_int64_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
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

static ssize_t gquic_frame_ack_deserialize(void *const frame, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    u_int8_t type;
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    type = ((u_int8_t *) buf)[off++];
    if (type != 0x02 && type != 0x03) {
        return -3;
    }
    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    size_t i = 0;
    for (i = 0; i < 4; i++) {
        deserialize_len = gquic_varint_deserialize(vars[i], buf + off, size - off);
        if (deserialize_len <= 0) {
            return -4;
        }
        off += deserialize_len;
    }
    for (i = 0; i < spec->count - 1; i++) {
        gquic_frame_ack_range_t *range = gquic_list_alloc(sizeof(gquic_frame_ack_range_t));
        if (gquic_list_insert_before(&spec->ranges, range) != 0) {
            return -4;
        }
        u_int64_t *range_vars[] = { &range->gap, &range->range };
        int j = 0;
        for (j = 0; j < 2; j++) {
            deserialize_len = gquic_varint_deserialize(range_vars[j], buf + off, size - off);
            if (deserialize_len <= 0) {
                return -4;
            }
            off += deserialize_len;
        }
    }

    if (GQUIC_FRAME_META(spec).type == 0x03) {
        u_int64_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
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

static int gquic_frame_ack_init(void *const frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    spec->count = 0;
    spec->delay = 0;
    spec->ecn.ecn_ce = 0;
    spec->ecn.ect[0] = 0;
    spec->ecn.ect[1] = 0;
    spec->first_range = 0;
    spec->largest_ack = 0;
    gquic_list_head_init(&spec->ranges);
    return 0;
}

static int gquic_frame_ack_release(void *const frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return -1;
    }
    while (gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->ranges)) != GQUIC_LIST_PAYLOAD(&spec->ranges)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->ranges)));
    }
    return 0;
}

int gquic_frame_ack_acks_packet(const gquic_list_t *const blocks, const u_int64_t pn) {
    gquic_frame_ack_block_t *block = NULL;
    if (blocks == NULL) {
        return 0;
    }
    if (pn < ((gquic_frame_ack_block_t *) GQUIC_LIST_LAST(&blocks))->smallest
        || ((gquic_frame_ack_block_t *) GQUIC_LIST_FIRST(&blocks))->largest < pn) {
        return 0;
    }
    GQUIC_LIST_FOREACH(block, &blocks) {
        if (pn >= block->smallest) {
            return pn <= block->largest;
        }
    }
    return 0;
}

int gquic_frame_ack_ranges_to_blocks(gquic_list_t *const blocks, const gquic_frame_ack_t *const spec) {
    gquic_frame_ack_block_t *block = NULL;
    gquic_frame_ack_range_t *range = NULL;
    u_int64_t largest = 0;
    u_int64_t smallest = 0;
    if (blocks == NULL || spec == NULL) {
        return -1;
    }
    largest = spec->largest_ack;
    smallest = largest - spec->first_range;
    if ((block = gquic_list_alloc(sizeof(gquic_frame_ack_block_t))) == NULL) {
        return -2;
    }
    block->largest = largest;
    block->smallest = smallest;
    gquic_list_insert_before(blocks, block);
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        largest = smallest - range->gap - 2;
        smallest = largest - range->range;
        if ((block = gquic_list_alloc(sizeof(gquic_frame_ack_block_t))) == NULL) {
            return -3;
        }
        block->largest = largest;
        block->smallest = smallest;
        gquic_list_insert_before(blocks, block);
    }
    return 0;
}

int gquic_frame_ack_ranges_from_blocks(gquic_frame_ack_t *const spec, const gquic_list_t *const blocks) {
    int is_first = 1;
    gquic_frame_ack_range_t *range = NULL;
    gquic_frame_ack_block_t *block = NULL;
    u_int64_t largest = 0;
    u_int64_t smallest = 0;
    if (spec == NULL || blocks == NULL) {
        return -1;
    }
    block = GQUIC_LIST_FIRST(blocks);
    largest = block->largest;
    smallest = block->smallest;
    spec->largest_ack = largest;
    spec->first_range = largest - smallest;
    spec->count = 0;
    GQUIC_LIST_FOREACH(block, blocks) {
        if (is_first) {
            is_first = 0;
            continue;
        }
        if ((range = gquic_list_alloc(sizeof(gquic_frame_ack_range_t))) == NULL) {
            return -2;
        }
        range->gap = smallest - block->largest - 2;
        range->range = block->largest - block->smallest;
        gquic_list_insert_before(&spec->ranges, range);
        spec->count++;
    }

    return 0;
}

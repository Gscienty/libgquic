/* src/frame/ack.c ACK frame 实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/ack.h"
#include "frame/meta.h"
#include "util/list.h"
#include "exception.h"
#include "log.h"

/**
 * ACK frame 大小
 *
 * @param frame: ACK frame
 * 
 * @return: frame大小
 */
static size_t gquic_frame_ack_size(const void *const frame);

/**
 * ACK frame序列化
 *
 * @param frame: ACK frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ack_serialize(const void *const frame, gquic_writer_str_t *const writer);

/**
 * ACK frame反序列化
 *
 * @param frame: ACK frame
 * @param reader: reader
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ack_deserialize(void *const frame, gquic_reader_str_t *const reader);

/**
 * ACK frame 初始化
 *
 * @param frame: ACK frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ack_init(void *const frame);

/**
 * 析构ACK frame
 *
 * @param frame: ACK frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ack_dtor(void *const frame);

gquic_exception_t gquic_frame_ack_range_init(gquic_frame_ack_range_t *const range) {
    if (range == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    range->gap = 0;
    range->range = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_frame_ack_alloc(gquic_frame_ack_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_ack_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x02;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_ack_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_ack_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_ack_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_ack_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_ack_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_ack_size(const void *const frame) {
    size_t ret = 0;
    const gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    ret = 1
        + gquic_varint_size(&spec->largest_ack)
        + gquic_varint_size(&spec->delay)
        + gquic_varint_size(&spec->count)
        + gquic_varint_size(&spec->first_range);

    gquic_frame_ack_range_t *range = NULL;
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        ret += gquic_varint_size(&range->gap) + gquic_varint_size(&range->range);
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        ret += gquic_varint_size(&spec->ecn.ect[0]) + gquic_varint_size(&spec->ecn.ect[1]) + gquic_varint_size(&spec->ecn.ecn_ce);
    }

    return ret;
}

static gquic_exception_t gquic_frame_ack_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_ack_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    int i = 0;
    for (i = 0; i < 4; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }
    gquic_frame_ack_range_t *range;
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        u_int64_t *vars[] = { &range->gap, &range->range };
        for (i = 0; i < 2; i++) {
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
        }
    }
    if (GQUIC_FRAME_META(spec).type == 0x03) {
        const u_int64_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
        for (i = 0; i < 3; i++) {
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ack_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    u_int8_t type;
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x02 && type != 0x03) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    
    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize ACK frame");

    GQUIC_FRAME_META(spec).type = type;
    u_int64_t *vars[] = { &spec->largest_ack, &spec->delay, &spec->count, &spec->first_range };
    size_t i = 0;
    for (i = 0; i < 4; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }
    if (spec->count != 0) {
        for (i = 0; i < spec->count - 1; i++) {
            gquic_frame_ack_range_t *range = NULL;
            GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &range, sizeof(gquic_frame_ack_range_t)));
            gquic_frame_ack_range_init(range);
            GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&spec->ranges, range));
            u_int64_t *range_vars[] = { &range->gap, &range->range };
            int j = 0;
            for (j = 0; j < 2; j++) {
                GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(range_vars[i], reader));
            }
        }
    }

    if (GQUIC_FRAME_META(spec).type == 0x03) {
        u_int64_t *vars[] = { &spec->ecn.ect[0], &spec->ecn.ect[1], &spec->ecn.ecn_ce };
        for (i = 0; i < 3; i++) {
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ack_init(void *const frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->count = 0;
    spec->delay = 0;
    spec->ecn.ecn_ce = 0;
    spec->ecn.ect[0] = 0;
    spec->ecn.ect[1] = 0;
    spec->first_range = 0;
    spec->largest_ack = 0;
    gquic_list_head_init(&spec->ranges);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ack_dtor(void *const frame) {
    gquic_frame_ack_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->ranges)) != GQUIC_LIST_PAYLOAD(&spec->ranges)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&spec->ranges)));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_frame_ack_blocks_contain_packet(const gquic_list_t *const blocks, const u_int64_t pn) {
    gquic_frame_ack_block_t *block = NULL;
    if (blocks == NULL) {
        return false;
    }
    if (pn < ((gquic_frame_ack_block_t *) GQUIC_LIST_LAST(&blocks))->smallest
        || ((gquic_frame_ack_block_t *) GQUIC_LIST_FIRST(&blocks))->largest < pn) {
        return false;
    }
    GQUIC_LIST_FOREACH(block, blocks) {
        if (pn >= block->smallest) {
            return pn <= block->largest;
        }
    }

    return false;
}

gquic_exception_t gquic_frame_ack_ranges_to_blocks(gquic_list_t *const blocks, const gquic_frame_ack_t *const spec) {
    gquic_frame_ack_block_t *block = NULL;
    gquic_frame_ack_range_t *range = NULL;
    u_int64_t largest = 0;
    u_int64_t smallest = 0;
    if (blocks == NULL || spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    largest = spec->largest_ack;
    smallest = largest - spec->first_range;
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &block, sizeof(gquic_frame_ack_block_t)));
    block->largest = largest;
    block->smallest = smallest;
    gquic_list_insert_before(blocks, block);
    GQUIC_LIST_FOREACH(range, &spec->ranges) {
        largest = smallest - range->gap - 2;
        smallest = largest - range->range;
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &block, sizeof(gquic_frame_ack_block_t)));
        block->largest = largest;
        block->smallest = smallest;
        gquic_list_insert_before(blocks, block);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_frame_ack_ranges_from_blocks(gquic_frame_ack_t *const spec, const gquic_list_t *const blocks) {
    bool is_first = true;
    gquic_frame_ack_range_t *range = NULL;
    gquic_frame_ack_block_t *block = NULL;
    u_int64_t largest = 0;
    u_int64_t smallest = 0;
    if (spec == NULL || blocks == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    block = GQUIC_LIST_FIRST(blocks);
    largest = block->largest;
    smallest = block->smallest;
    spec->largest_ack = largest;
    spec->first_range = largest - smallest;
    spec->count = 0;
    GQUIC_LIST_FOREACH(block, blocks) {
        if (is_first) {
            is_first = false;
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &range, sizeof(gquic_frame_ack_range_t)));
        range->gap = smallest - block->largest - 2;
        range->range = block->largest - block->smallest;
        gquic_list_insert_before(&spec->ranges, range);
        spec->count++;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_frames_has_frame_ack(gquic_list_t *const frames) {
    void **frame_storage = NULL;
    GQUIC_LIST_FOREACH(frame_storage, frames) {
        if (GQUIC_FRAME_META(*frame_storage).type == 0x02 || GQUIC_FRAME_META(*frame_storage).type == 0x03) {
            return true;
        }
    }
    return false;
}

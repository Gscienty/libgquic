/* src/frame/stream.c STREAM frame 实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/streams_blocked.h"
#include "frame/meta.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

/**
 * STREAMS_BLOCKED frame 大小
 *
 * @param frame: STREAMS_BLOCKED frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_streams_blocked_size(const void *const);

/**
 * STREAMS_BLOCKED frame 序列化
 *
 * @param frame: STREAMS_BLOCKED frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_streams_blocked_serialize(const void *const, gquic_writer_str_t *const);

/**
 * STREAMS_BLOCKED frame 反序列化
 *
 * @param frame: STREAMS_BLOCKED frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_streams_blocked_deserialize(void *const, gquic_reader_str_t *const);

/**
 * STREAMS_BLOCKED frame 初始化
 *
 * @param frame: STREAMS_BLOCKED frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_streams_blocked_init(void *const);

/**
 * 析构 STREAMS_BLOCKED frame
 * 
 * @param frame: STREAMS_BLOCKED frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_streams_blocked_dtor(void *const);

gquic_exception_t gquic_frame_streams_blocked_alloc(gquic_frame_streams_blocked_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_streams_blocked_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x00;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_streams_blocked_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_streams_blocked_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_streams_blocked_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_streams_blocked_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_streams_blocked_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_streams_blocked_size(const void *const frame) {
    const gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    
    return 1 + gquic_varint_size(&spec->limit);
}

static gquic_exception_t gquic_frame_streams_blocked_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->limit, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_streams_blocked_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_streams_blocked_t *spec = frame;
    u_int8_t type;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = gquic_reader_str_read_byte(reader);
    if (type != 0x16 && type != 0x17) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize STREAMS_BLOCKED frame");

    GQUIC_FRAME_META(spec).type = type;
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->limit, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_streams_blocked_init(void *const frame) {
    gquic_frame_streams_blocked_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->limit = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_streams_blocked_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


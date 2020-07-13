/* src/frame/ping.c PING frame实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/meta.h"
#include "frame/ping.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

/**
 * PING frame 大小
 *
 * @param frame: PING frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_ping_size(const void *const);

/**
 * PING frame 序列化
 *
 * @param frame: PING frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ping_serialize(const void *const, gquic_writer_str_t *const);

/**
 * PING frame 反序列化
 *
 * @param frame: PING frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_ping_deserialize(void *const, gquic_reader_str_t *const);

/**
 * PING frame 初始化
 *
 * @param frame: PING frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ping_init(void *const);

/**
 * 析构 PING frame
 * 
 * @param frame: PING frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_ping_dtor(void *const);

gquic_exception_t gquic_frame_ping_alloc(gquic_frame_ping_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_ping_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x01;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_ping_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_ping_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_ping_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_ping_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_ping_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_ping_size(const void *const frame) {
    (void) frame;

    return 1;
}

static gquic_exception_t gquic_frame_ping_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    size_t used_size = GQUIC_FRAME_META(frame).size_func(frame);
    if (used_size > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, 0x01));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ping_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    (void) frame;
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 1));

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize PING frame");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ping_init(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_ping_dtor(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


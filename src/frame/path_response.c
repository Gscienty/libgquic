/* src/frame/path_response.c PATH_RESPONSE frame实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/path_response.h"
#include "frame/meta.h"
#include "exception.h"
#include "log.h"
#include <string.h>

/**
 * PATH_RESPONSE frame 大小
 *
 * @param frame: PATH_RESPONSE frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_path_response_size(const void *const);

/**
 * PATH_RESPONSE frame 序列化
 *
 * @param frame: PATH_RESPONSE frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_path_response_serialize(const void *const, gquic_writer_str_t *const);

/**
 * PATH_RESPONSE frame 反序列化
 *
 * @param frame: PATH_RESPONSE frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_path_response_deserialize(void *const, gquic_reader_str_t *const);

/**
 * PATH_RESPONSE frame 初始化
 *
 * @param frame: PATH_RESPONSE frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_path_response_init(void *const);

/**
 * 析构 PATH_RESPONSE frame
 * 
 * @param frame: PATH_RESPONSE frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_path_response_dtor(void *const);

gquic_exception_t gquic_frame_path_response_alloc(gquic_frame_path_response_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_path_response_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x1b;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_path_response_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_path_response_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_path_response_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_path_response_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_path_response_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_path_response_size(const void *const frame) {
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }
    return 1 + 8;
}

static gquic_exception_t gquic_frame_path_response_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_path_response_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    gquic_str_t data = { 8, (void *) spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &data));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_path_response_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_path_response_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize PATH_RESPONSE frame");

    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }
    gquic_str_t data = { 8, spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&data, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_path_response_init(void *const frame) {
    (void) frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_path_response_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


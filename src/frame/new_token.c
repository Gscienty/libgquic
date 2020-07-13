/* src/frame/new_token.c NEW_TOKEN frame实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/new_token.h"
#include "frame/meta.h"
#include "util/malloc.h"
#include "exception.h"
#include "log.h"
#include <string.h>

/**
 * NEW_TOKEN frame 大小
 *
 * @param frame: NEW_TOKEN frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_new_token_size(const void *const);

/**
 * NEW_TOKEN frame 序列化
 *
 * @param frame: NEW_TOKEN frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_token_serialize(const void *const, gquic_writer_str_t *const);

/**
 * NEW_TOKEN frame 反序列化
 *
 * @param frame: NEW_TOKEN frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_token_deserialize(void *const, gquic_reader_str_t *const);

/**
 * NEW_TOKEN frame 初始化
 *
 * @param frame: NEW_TOKEN frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_token_init(void *const);

/**
 * 析构 NEW_TOKEN frame
 * 
 * @param frame: NEW_TOKEN frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_token_dtor(void *const);

gquic_exception_t gquic_frame_new_token_alloc(gquic_frame_new_token_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_new_token_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x07;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_new_token_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_new_token_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_new_token_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_new_token_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_new_token_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_new_token_size(const void *const frame) {
    const gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->len) + spec->len;
}

static gquic_exception_t gquic_frame_new_token_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&spec->len, writer));
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &token));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_token_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize NEW_TOKEN frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&spec->len, reader));
    if (spec->len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &spec->token, spec->len));
    gquic_str_t token = { spec->len, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_token_init(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->len = 0;
    spec->token = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_token_dtor(void *const frame) {
    gquic_frame_new_token_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (spec->token != NULL) {
        gquic_free(spec->token);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/* src/frame/crypto.c CRYPTO frame 实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/crypto.h"
#include "frame/meta.h"
#include "util/malloc.h"
#include "exception.h"
#include "log.h"
#include <string.h>

/**
 * CRYPTO frame 大小
 *
 * @param frame: CRYPTO frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_crypto_size(const void *const frame);

/**
 * CRYPTO frame 序列化
 *
 * @param frame: CRYPTO frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_crypto_serialize(const void *const frame, gquic_writer_str_t *const writer);

/**
 * CRYPTO frame 反序列化
 *
 * @param frame: CRYPTO frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_crypto_deserialize(void *const frame, gquic_reader_str_t *const reader);

/**
 * CRYPTO frame 初始化
 *
 * @param frame: CRYPTO frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_crypto_init(void *const frame);

/**
 * 析构 CRYPTO frame
 * 
 * @param frame: CRYPTO frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_crypto_dtor(void *const frame);

gquic_exception_t gquic_frame_crypto_alloc(gquic_frame_crypto_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_crypto_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x06;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_crypto_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_crypto_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_crypto_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_crypto_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_crypto_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_crypto_size(const void *const frame) {
    const gquic_frame_crypto_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->len) + gquic_varint_size(&spec->off) + spec->len;
}

static gquic_exception_t gquic_frame_crypto_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    const gquic_frame_crypto_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(frame).type));
    const u_int64_t *vars[] = { &spec->off, &spec->len };
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }
    gquic_str_t data = { spec->len, spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &data));
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
 }

static gquic_exception_t gquic_frame_crypto_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    int i;
    gquic_frame_crypto_t *spec = frame;
    if (frame == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(frame).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize CRYPTO frame");

    u_int64_t *vars[] = { &spec->off, &spec->len };
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }
    if (spec->len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &spec->data, spec->len));
    gquic_str_t data = { spec->len, spec->data };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&data, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_crypto_init(void *const frame) {
    gquic_frame_crypto_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->off = 0;
    spec->len = 0;
    spec->data = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_crypto_dtor(void *const frame) {
    gquic_frame_crypto_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (spec->data != NULL) {
        gquic_free(spec->data);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

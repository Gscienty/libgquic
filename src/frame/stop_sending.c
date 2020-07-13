/* src/frame/stop_sending.c STOP_SENDING frame实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/stop_sending.h"
#include "frame/meta.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

/**
 * STOP_SENDING frame 大小
 *
 * @param frame: STOP_SENDING frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_stop_sending_size(const void *const);

/**
 * STOP_SENDING frame 序列化
 *
 * @param frame: STOP_SENDING frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_stop_sending_serialize(const void *const, gquic_writer_str_t *const);

/**
 * STOP_SENDING frame 反序列化
 *
 * @param frame: STOP_SENDING frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_stop_sending_deserialize(void *const, gquic_reader_str_t *const);

/**
 * STOP_SENDING frame 初始化
 *
 * @param frame: STOP_SENDING frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_stop_sending_init(void *const);

/**
 * 析构 STOP_SENDING frame
 * 
 * @param frame: STOP_SENDING frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_stop_sending_dtor(void *const);

gquic_exception_t gquic_frame_stop_sending_alloc(gquic_frame_stop_sending_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_stop_sending_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x05;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_stop_sending_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_stop_sending_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_stop_sending_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_stop_sending_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_stop_sending_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_stop_sending_size(const void *const frame) {
    const gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->id) + gquic_varint_size(&spec->errcode);
}

static gquic_exception_t gquic_frame_stop_sending_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    int i;
    const gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[] = { &spec->id, &spec->errcode };
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer) != 0);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_stop_sending_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_stop_sending_t *spec = frame;
    if (frame == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(frame).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize STOP_SENDING frame");
    
    u_int64_t *vars[] = { &spec->id, &spec->errcode };
    int i;
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_stop_sending_init(void *const frame) {
    gquic_frame_stop_sending_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->errcode = 0;
    spec->id = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_stop_sending_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


/* src/frame/new_connection_id.c NEW_CONNECTION_ID frame实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "frame/new_connection_id.h"
#include "frame/meta.h"
#include "exception.h"
#include "log.h"
#include <string.h>

/**
 * NEW_CONNECTION_ID frame 大小
 *
 * @param frame: NEW_CONNECTION_ID frame
 * 
 * @return frame大小
 */
static size_t gquic_frame_new_connection_id_size(const void *const);

/**
 * NEW_CONNECTION_ID frame 序列化
 *
 * @param frame: NEW_CONNECTION_ID frame
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_connection_id_serialize(const void *const, gquic_writer_str_t *const);

/**
 * NEW_CONNECTION_ID frame 反序列化
 *
 * @param frame: NEW_CONNECTION_ID frame
 * @param reader: reader
 *
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_connection_id_deserialize(void *const, gquic_reader_str_t *const);

/**
 * NEW_CONNECTION_ID frame 初始化
 *
 * @param frame: NEW_CONNECTION_ID frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_connection_id_init(void *const);

/**
 * 析构 NEW_CONNECTION_ID frame
 * 
 * @param frame: NEW_CONNECTION_ID frame
 * 
 * @return: exception
 */
static gquic_exception_t gquic_frame_new_connection_id_dtor(void *const);

gquic_exception_t gquic_frame_new_connection_id_alloc(gquic_frame_new_connection_id_t **const frame_storage) {
    if (frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_ALLOC(frame_storage, gquic_frame_new_connection_id_t));

    GQUIC_FRAME_META(*frame_storage).type = 0x18;
    GQUIC_FRAME_META(*frame_storage).deserialize_func = gquic_frame_new_connection_id_deserialize;
    GQUIC_FRAME_META(*frame_storage).init_func = gquic_frame_new_connection_id_init;
    GQUIC_FRAME_META(*frame_storage).dtor_func = gquic_frame_new_connection_id_dtor;
    GQUIC_FRAME_META(*frame_storage).serialize_func = gquic_frame_new_connection_id_serialize;
    GQUIC_FRAME_META(*frame_storage).size_func = gquic_frame_new_connection_id_size;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static size_t gquic_frame_new_connection_id_size(const void *const frame) {
    const gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        return 0;
    }

    return 1 + gquic_varint_size(&spec->seq) + gquic_varint_size(&spec->prior) + 1 + spec->len + 16;
}

static gquic_exception_t gquic_frame_new_connection_id_serialize(const void *const frame, gquic_writer_str_t *const writer) {
    const gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_FRAME_SIZE(spec) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, GQUIC_FRAME_META(spec).type));
    const u_int64_t *vars[2] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(vars[i], writer));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write_byte(writer, spec->len));
    gquic_str_t conn_id = { spec->len, (void *) spec->conn_id };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &conn_id));
    gquic_str_t token = { 16, (void *) spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &token));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_connection_id_deserialize(void *const frame, gquic_reader_str_t *const reader) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_FRAME_META(spec).type) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "deserialize NEW_CONNECTION_ID frame");

    u_int64_t *vars[] = { &spec->seq, &spec->prior };
    int i = 0;
    for (i = 0; i < 2; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(vars[i], reader));
    }
    spec->len = gquic_reader_str_read_byte(reader);
    gquic_str_t conn_id = { spec->len, spec->conn_id };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&conn_id, reader));
    gquic_str_t token = { 16, spec->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_connection_id_init(void *const frame) {
    gquic_frame_new_connection_id_t *spec = frame;
    if (spec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->prior = 0;
    spec->seq = 0;
    spec->len = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_frame_new_connection_id_dtor(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

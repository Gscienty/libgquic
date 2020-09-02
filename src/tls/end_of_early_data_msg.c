/* src/tls/end_of_early_data_msg.c TLS END_OF_EARLY_DATA record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/end_of_early_data_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static gquic_exception_t gquic_tls_end_of_early_data_msg_init(void *const msg);
static gquic_exception_t gquic_tls_end_of_early_data_msg_dtor(void *const msg);
static ssize_t gquic_tls_end_of_early_data_msg_size(const void *const msg);
static gquic_exception_t gquic_tls_end_of_early_data_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static gquic_exception_t gquic_tls_end_of_early_data_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_exception_t gquic_tls_end_of_early_data_msg_alloc(gquic_tls_end_of_early_data_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_end_of_early_data_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_end_of_early_data_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_end_of_early_data_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_end_of_early_data_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_end_of_early_data_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_end_of_early_data_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_end_of_early_data_msg_init(void *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_end_of_early_data_msg_dtor(void *const msg) {
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_end_of_early_data_msg_size(const void *const msg) {
    if (msg == NULL) {
        return 0;
    }
    return 4;
}

static gquic_exception_t gquic_tls_end_of_early_data_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_end_of_early_data_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA));
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, 0));
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, 0));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_end_of_early_data_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 3));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

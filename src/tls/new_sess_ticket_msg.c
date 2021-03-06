/* src/tls/new_sess_ticket_msg.c TLS NEW_SESS_TICKET record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/new_sess_ticket_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/list.h"
#include <unistd.h>

static gquic_exception_t gquic_tls_new_sess_ticket_msg_init(void *const msg);
static gquic_exception_t gquic_tls_new_sess_ticket_msg_dtor(void *const msg);
static ssize_t gquic_tls_new_sess_ticket_msg_size(const void *const msg);
static gquic_exception_t gquic_tls_new_sess_ticket_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static gquic_exception_t gquic_tls_new_sess_ticket_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_exception_t gquic_tls_new_sess_ticket_msg_alloc(gquic_tls_new_sess_ticket_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_new_sess_ticket_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_new_sess_ticket_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_new_sess_ticket_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_new_sess_ticket_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_new_sess_ticket_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_new_sess_ticket_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_new_sess_ticket_msg_init(void *const msg) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->age_add = 0;
    spec->lifetime = 0;
    spec->max_early_data = 0;
    gquic_str_init(&spec->label);
    gquic_str_init(&spec->nonce);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_new_sess_ticket_msg_dtor(void *const msg) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->label);
    gquic_str_reset(&spec->nonce);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_new_sess_ticket_msg_size(const void *const msg) {
    const gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        return 0;
    }
    return 1 + 3 + 4 + 4 + 1 + spec->nonce.size + 2 + spec->label.size + 2 + (spec->max_early_data > 0 ? 2 + 2 + 4 : 0);
}

static gquic_exception_t gquic_tls_new_sess_ticket_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    int _lazy = 0;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_new_sess_ticket_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);

    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET));
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 3));
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, spec->lifetime));
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, spec->age_add));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &spec->nonce, 1));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &spec->label, 2));
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
    if (spec->max_early_data > 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_EARLY_DATA));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, spec->max_early_data));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }
    for (_lazy = 0; _lazy < 2; _lazy++) GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_new_sess_ticket_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    size_t prefix_len = 0;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 3, reader));
    if ((size_t) prefix_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&spec->lifetime, 4, reader));
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&spec->age_add, 4, reader));
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->nonce, 1, reader));
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->label, 2, reader));
    prefix_len = 0;
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
    if (prefix_len > 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2 + 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&spec->max_early_data, 4, reader));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

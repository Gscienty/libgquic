/* src/tls/cert_verify_msg.c TLS CERT_VERIFY record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/cert_verify_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/list.h"
#include <unistd.h>

static gquic_exception_t gquic_tls_cert_verify_msg_init(void *const msg);
static gquic_exception_t gquic_tls_cert_verify_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_verify_msg_size(const void *const msg);
static gquic_exception_t gquic_tls_cert_verify_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static gquic_exception_t gquic_tls_cert_verify_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_exception_t gquic_tls_cert_verify_msg_alloc(gquic_tls_cert_verify_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_cert_verify_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_cert_verify_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_cert_verify_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_cert_verify_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_cert_verify_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_cert_verify_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_cert_verify_msg_init(void *const msg) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->has_sign_algo = 1;
    spec->sign_algo = 0;
    gquic_str_init(&spec->sign);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_cert_verify_msg_dtor(void *const msg) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->sign);
    gquic_tls_cert_verify_msg_init(spec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

ssize_t gquic_tls_cert_verify_msg_size(const void *const msg) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return 0;
    }
    return 1 + 3 + (spec->has_sign_algo ? 2 : 0) + 2 + spec->sign.size;
}

static gquic_exception_t gquic_tls_cert_verify_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_cert_verify_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY));
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 3));
    if (spec->has_sign_algo) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, spec->sign_algo));
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &spec->sign, 2));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_cert_verify_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 3));
    if (spec->has_sign_algo) {
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&spec->sign_algo, 2, reader));
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->sign, 2, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


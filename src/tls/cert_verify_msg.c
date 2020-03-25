#include "tls/cert_verify_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/list.h"
#include <unistd.h>

static int gquic_tls_cert_verify_msg_init(void *const msg);
static int gquic_tls_cert_verify_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_verify_msg_size(const void *const msg);
static int gquic_tls_cert_verify_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_cert_verify_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_cert_verify_msg_t *gquic_tls_cert_verify_msg_alloc() {
    gquic_tls_cert_verify_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_cert_verify_msg_t)); 
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_cert_verify_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_cert_verify_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_cert_verify_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_cert_verify_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_cert_verify_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY;

    return msg;
}

static int gquic_tls_cert_verify_msg_init(void *const msg) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    spec->has_sign_algo = 1;
    spec->sign_algo = 0;
    gquic_str_init(&spec->sign);

    return GQUIC_SUCCESS;
}

static int gquic_tls_cert_verify_msg_dtor(void *const msg) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_str_reset(&spec->sign);
    gquic_tls_cert_verify_msg_init(spec);

    return GQUIC_SUCCESS;
}

ssize_t gquic_tls_cert_verify_msg_size(const void *const msg) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return 0;
    }
    return 1 + 3 + (spec->has_sign_algo ? 2 : 0) + 2 + spec->sign.size;
}

static int gquic_tls_cert_verify_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((size_t) gquic_tls_cert_verify_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    if (spec->has_sign_algo) {
        gquic_big_endian_writer_2byte(writer, spec->sign_algo);
    }
    __gquic_fill_str(writer, &spec->sign, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    return GQUIC_SUCCESS;
}

static int gquic_tls_cert_verify_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        return GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED;
    }
    gquic_reader_str_readed_size(reader, 3);
    if (spec->has_sign_algo) {
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&spec->sign_algo, 2, reader));
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->sign, 2, reader));

    return GQUIC_SUCCESS;
}


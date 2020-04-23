#include "tls/cert_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"

static int gquic_tls_cert_msg_init(void *const msg);
static int gquic_tls_cert_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_msg_size(const void *const msg);
static int gquic_tls_cert_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_cert_msg_deserialize(void *const msg, gquic_reader_str_t *const);

int gquic_tls_cert_msg_alloc(gquic_tls_cert_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_cert_msg_t)));

    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_cert_msg_init;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_cert_msg_dtor;
    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_cert_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_cert_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_cert_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_msg_init(void *const msg) {
    gquic_tls_cert_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_init(&spec->cert));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_msg_dtor(void *const msg) {
    gquic_tls_cert_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_dtor(&spec->cert));
    gquic_tls_cert_msg_init(msg);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_cert_msg_size(const void *const msg) {
    const gquic_tls_cert_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 1 + gquic_tls_cert_size(&spec->cert);
}

static int gquic_tls_cert_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    gquic_list_t prefix_len_stack;
    const gquic_tls_cert_msg_t *const spec = msg;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_cert_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT));
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 3));
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, 0));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_serialize(&spec->cert, writer));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    u_int64_t cert_len = 0;
    gquic_tls_cert_msg_t *const spec = msg;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&cert_len, 3, reader));
    gquic_reader_str_t cert_reader = { cert_len, GQUIC_STR_VAL(reader) };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read_byte(&cert_reader));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_deserialize(&spec->cert, &cert_reader));
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, GQUIC_STR_VAL(&cert_reader) - GQUIC_STR_VAL(reader)));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

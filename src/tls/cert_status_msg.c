#include "tls/cert_status_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_cert_status_msg_init(void *const msg);
static int gquic_tls_cert_status_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_status_msg_size(const void *const msg);
static int gquic_tls_cert_status_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_cert_status_msg_deserialize(void *const msg, gquic_reader_str_t *const);

int gquic_tls_cert_status_msg_alloc(gquic_tls_cert_status_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_cert_status_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_cert_status_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_cert_status_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_cert_status_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_cert_status_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_cert_status_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_status_msg_init(void *const msg) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&spec->res);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_status_msg_dtor(void *const msg) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->res);
    gquic_tls_cert_status_msg_init(spec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_cert_status_msg_size(const void *const msg) {
    const gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        return 0;
    }
    return 1 + 3 + spec->res.size;
}

static int gquic_tls_cert_status_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_cert_status_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_cert_status_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS);
    __gquic_fill_str(writer, &spec->res, 3);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_status_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->res, 3, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

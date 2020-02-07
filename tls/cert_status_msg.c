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

gquic_tls_cert_status_msg_t *gquic_tls_cert_status_msg_alloc() {
    gquic_tls_cert_status_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_cert_status_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_cert_status_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_cert_status_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_cert_status_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_cert_status_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_cert_status_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS;

    return msg;
}

static int gquic_tls_cert_status_msg_init(void *const msg) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    gquic_str_init(&spec->res);
    return 0;
}

static int gquic_tls_cert_status_msg_dtor(void *const msg) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&spec->res);
    gquic_tls_cert_status_msg_init(spec);
    return 0;
}

static ssize_t gquic_tls_cert_status_msg_size(const void *const msg) {
    const gquic_tls_cert_status_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + spec->res.size;
}

static int gquic_tls_cert_status_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_cert_status_msg_t *const spec = msg;
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_status_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS);
    __gquic_fill_str(writer, &spec->res, 3);
    return off;
}

static int gquic_tls_cert_status_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_cert_status_msg_t *const spec = msg;
    size_t off = 0;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS) {
        return -2;
    }
    if (__gquic_recovery_str(&spec->res, 3, reader) != 0) {
        return -3;
    }
    return off;
}

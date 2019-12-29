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
static ssize_t gquic_tls_cert_verify_msg_serialize(const void *const msg, void *const buf, const size_t size);
static ssize_t gquic_tls_cert_verify_msg_deserialize(void *const msg, const void *const buf, const size_t size);

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
        return -1;
    }
    spec->has_sign_algo = 1;
    spec->sign_algo = 0;
    gquic_str_init(&spec->sign);
    return 0;
}

static int gquic_tls_cert_verify_msg_dtor(void *const msg) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&spec->sign);
    gquic_tls_cert_verify_msg_init(spec);
    return 0;
}

ssize_t gquic_tls_cert_verify_msg_size(const void *const msg) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + (spec->has_sign_algo ? 2 : 0) + 2 + spec->sign.size;
}

static ssize_t gquic_tls_cert_verify_msg_serialize(const void *const msg, void *const buf, const size_t size) {
    const gquic_tls_cert_verify_msg_t *const spec = msg;
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_verify_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    if (spec->has_sign_algo) {
        __gquic_fill_2byte(buf, &off, spec->sign_algo);
    }
    __gquic_fill_str_full(buf, &off, &spec->sign, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

static ssize_t gquic_tls_cert_verify_msg_deserialize(void *const msg, const void *const buf, const size_t size) {
    gquic_tls_cert_verify_msg_t *const spec = msg;
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        return -2;
    }
    off += 3;
    if (spec->has_sign_algo) {
        if (__gquic_recovery_bytes(&spec->sign_algo, 2, buf, size, &off) != 0) {
            return -2;
        }
    }
    if (__gquic_recovery_str_full(&spec->sign, 2, buf, size, &off) != 0) {
        return -2;
    }

    return off;
}


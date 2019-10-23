#include "tls/cert_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "util/str.h"

int gquic_tls_cert_msg_init(gquic_tls_cert_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_list_head_init(&msg->certs);
    return 0;
}

int gquic_tls_cert_msg_reset(gquic_tls_cert_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    while (!gquic_list_head_empty(&msg->certs)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->certs)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->certs)));
    }
    gquic_tls_cert_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_cert_msg_size(const gquic_tls_cert_msg_t *msg) {
    size_t off = 0;
    gquic_str_t *field;
    if (msg == NULL) {
        return -1;
    }
    off += 1 + 3 + 3;
    GQUIC_LIST_FOREACH(field, &msg->certs) off += 3 + field->size;
    return off;
}

ssize_t gquic_tls_cert_msg_serialize(const gquic_tls_cert_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    gquic_str_t *field;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_msg_size(msg) > size) {
        return -2;
    }
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT);
    gquic_list_head_init(&prefix_len_stack);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    GQUIC_LIST_FOREACH(field, &msg->certs) {
        __gquic_fill_str_full(buf, &off, field, 3);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_cert_msg_deserialize(gquic_tls_cert_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    size_t prefix_len = 0;
    size_t start_position = 0;
    gquic_str_t *field = NULL;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT) {
        return -2;
    }
    off += 3;
    if (__gquic_recovery_bytes(&prefix_len, 3, buf, size, &off) != 0) {
        return -3;
    }
    if (prefix_len > size - off) {
        return -3;
    }
    for(start_position = off; off - start_position < prefix_len;) {
        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
            return -3;
        }
        if (__gquic_recovery_str_full(field, 3, buf, size, &off) != 0) {
            return -3;
        }
        if (gquic_list_insert_before(&msg->certs, field) != 0) {
            return -3;
        }
    }
    return off;
}


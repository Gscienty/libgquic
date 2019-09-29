#include "tls/cert_13_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/config.h"

int gquic_tls_cert_13_msg_init(gquic_tls_cert_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    if (gquic_tls_cert_init(&msg->cert) != 0) {
        return -2;
    }
    return 0;
}

int gquic_tls_cert_13_msg_reset(gquic_tls_cert_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    if (gquic_tls_cert_reset(&msg->cert) != 0) {
        return -2;
    }
    gquic_tls_cert_13_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_cert_13_msg_size(const gquic_tls_cert_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 1 + gquic_tls_cert_size(&msg->cert);
}

ssize_t gquic_tls_cert_13_msg_serialize(const gquic_tls_cert_13_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_13_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_1byte(buf, &off, 0);
    if ((ret = gquic_tls_cert_serialize(&msg->cert, buf + off, size - off)) < 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_cert_13_msg_deserialize(gquic_tls_cert_13_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT) {
        return -2;
    }
    off += 3 + 1;
    if ((ret = gquic_tls_cert_deserialize(&msg->cert, buf + off, size - off)) < 0) {
        return -2;
    }
    return off + ret;
}

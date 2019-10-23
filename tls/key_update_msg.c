#include "tls/key_update_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include <unistd.h>

int gquic_tls_key_update_msg_init(gquic_tls_key_update_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->req = 0;
    return 0;
}

int gquic_tls_key_update_msg_reset(gquic_tls_key_update_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

ssize_t gquic_tls_key_update_msg_size(const gquic_tls_key_update_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 1;
}

ssize_t gquic_tls_key_update_msg_serialize(const gquic_tls_key_update_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_key_update_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    if (msg->req) {
        __gquic_fill_1byte(buf, &off, 1);
    }
    else {
        __gquic_fill_1byte(buf, &off, 0);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

ssize_t gquic_tls_key_update_msg_deserialize(gquic_tls_key_update_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    size_t prefix_len = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE) {
        return -2;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 3, buf, size, &off) != 0) {
        return -2;
    }
    if (prefix_len > size - off) {
        return -2;
    }
    if (__gquic_recovery_bytes(&msg->req, 1, buf, size, &off) != 0) {
        return -2;
    }
    return off;
}


#include "tls/next_proto_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/config.h"
#include <unistd.h>

int gquic_tls_next_proto_msg_init(gquic_tls_next_proto_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_init(&msg->verify);
    return 0;
}

int gquic_tls_next_proto_msg_reset(gquic_tls_next_proto_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->verify);
    gquic_tls_next_proto_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_next_proto_msg_size(const gquic_tls_next_proto_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + msg->verify.size;
}

ssize_t gquic_tls_next_proto_msg_serialize(const gquic_tls_next_proto_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_next_proto_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_str_full(buf, &off, &msg->verify, 1);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_next_proto_msg_deserialize(gquic_tls_next_proto_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO) {
        return -2;
    }
    off += 3;
    if (__gquic_recovery_str_full(&msg->verify, 1, buf, size, &off) != 0) {
        return -2;
    }
    return off;
}

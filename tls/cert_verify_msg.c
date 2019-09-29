#include "tls/cert_verify_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/config.h"
#include "util/list.h"
#include <unistd.h>

int gquic_tls_cert_verify_msg_init(gquic_tls_cert_verify_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->has_sign_algo = 0;
    msg->sign_algo = 0;
    gquic_str_init(&msg->sign);
    return 0;
}

int gquic_tls_cert_verify_msg_reset(gquic_tls_cert_verify_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->sign);
    gquic_tls_cert_verify_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_cert_verify_msg_size(const gquic_tls_cert_verify_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + (msg->has_sign_algo ? 2 : 0) + 2 + msg->sign.size;
}

ssize_t gquic_tls_cert_verify_msg_serialize(const gquic_tls_cert_verify_msg_t *msg, void *buf, const size_t size) {
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
    if (msg->has_sign_algo) {
        __gquic_fill_2byte(buf, &off, msg->sign_algo);
    }
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    __gquic_fill_str(buf, &off, &msg->sign);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_cert_verify_msg_deserialize(gquic_tls_cert_verify_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        return -2;
    }
    off += 3;
    if (msg->has_sign_algo) {
        if (__gquic_recovery_bytes(&msg->sign_algo, 2, buf, size, &off) != 0) {
            return -2;
        }
    }
    if (__gquic_recovery_bytes(&msg->sign.size, 2, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str(&msg->sign, msg->sign.size, buf, size, &off) != 0) {
        return -2;
    }

    return off;
}

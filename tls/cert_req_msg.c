#include "tls/cert_req_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"

int gquic_tls_cert_req_msg_init(gquic_tls_cert_req_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->has_sign_algo = 0;
    gquic_str_init(&msg->cert_types);
    gquic_list_head_init(&msg->cert_auths);
    gquic_list_head_init(&msg->supported_sign_algos);
    return 0;
}

int gquic_tls_cert_req_msg_reset(gquic_tls_cert_req_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->cert_types);
    while (!gquic_list_head_empty(&msg->supported_sign_algos)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_sign_algos)));
    }
    while (!gquic_list_head_empty(&msg->cert_auths)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->cert_auths)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->cert_auths)));
    }

    gquic_tls_cert_req_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_cert_req_msg_size(const gquic_tls_cert_req_msg_t *msg) {
    size_t off = 0;
    void *_;
    if (msg == NULL) {
        return -1;
    }
    off += 1 + 3;
    // cert_types
    off += 1 + msg->cert_types.size;
    // sign_algos
    if (msg->has_sign_algo) {
        off += 2;
        GQUIC_LIST_FOREACH(_, &msg->supported_sign_algos) off += 2;
    }
    // cert_auths
    off += 2;
    GQUIC_LIST_FOREACH(_, &msg->cert_auths) off += 2 + ((gquic_str_t *) _)->size;
    return off;
}

ssize_t gquic_tls_cert_req_msg_serialize(const gquic_tls_cert_req_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    void *field;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_req_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_str_full(buf, &off, &msg->cert_types, 1);
    if (msg->has_sign_algo) {
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        GQUIC_LIST_FOREACH(field, &msg->supported_sign_algos) __gquic_fill_2byte(buf, &off, *(u_int16_t *) field);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    GQUIC_LIST_FOREACH(field, &msg->cert_auths) {
        __gquic_fill_str_full(buf, &off, field, 2);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

ssize_t gquic_tls_cert_req_msg_deserialize(gquic_tls_cert_req_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    size_t _ = 0;
    size_t prefix_len = 0;
    void *field = NULL;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ) {
        return -2;
    }
    off += 3;
    if (msg->has_sign_algo) {
        prefix_len = 0;
        if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
            return -2;
        }
        for (_ = off; off - _ < prefix_len;) {
            if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                return -2;
            }
            *(u_int16_t *) field = 0;
            if (__gquic_recovery_bytes(field, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (gquic_list_insert_before(&msg->supported_sign_algos, field) != 0) {
                return -2;
            }
        }
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
        return -2;
    }
    for (_ = off; off - _ < prefix_len;) {
        if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
            return -2;
        }
        if (__gquic_recovery_str_full(field, 2, buf, size, &off) != 0) {
            return -2;
        }
        if (gquic_list_insert_before(&msg->cert_auths, field) != 0) {
            return -2;
        }
    }

    return off;
}


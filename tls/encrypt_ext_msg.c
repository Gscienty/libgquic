#include "tls/encrypt_ext_msg.h"
#include "tls/config.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/_msg_serialize_util.h"

static ssize_t gquic_tls_encrypt_ext_msg_optional_deserialize(gquic_tls_encrypt_ext_msg_t *, const void *, const size_t);

int gquic_tls_encrypt_ext_msg_init(gquic_tls_encrypt_ext_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_init(&msg->alpn_proto);
    gquic_list_head_init(&msg->addition_exts);

    return 0;
}

int gquic_tls_encrypt_ext_msg_reset(gquic_tls_encrypt_ext_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->alpn_proto);
    while (!gquic_list_head_empty(&msg->addition_exts)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->addition_exts)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->addition_exts)));
    }
    return 0;
}

ssize_t gquic_tls_encrypt_ext_msg_size(const gquic_tls_encrypt_ext_msg_t *msg) {
    size_t off = 0;
    if (msg == NULL) {
        return -1;
    }
    // encrypted extensions
    off += 1;
    // payload len
    off += 3;
    // payload len (x2)
    off += 2;
    // alpn
    if (msg->alpn_proto.size > 0) off += 2 + 2 + 2 + 1 + msg->alpn_proto.size;
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->addition_exts) off += 2 + 2 + ext->data.size;
    return off;
}

ssize_t gquic_tls_encrypt_ext_msg_serialize(const gquic_tls_encrypt_ext_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_encrypt_ext_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    // server_hello
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS);

    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if (msg->alpn_proto.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_ALPN);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        __gquic_fill_str(buf, &off, &msg->alpn_proto);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->addition_exts) {
        __gquic_fill_2byte(buf, &off, ext->type);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str(buf, &off, &ext->data);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_encrypt_ext_msg_deserialize(gquic_tls_encrypt_ext_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t prefix_len = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS) {
        return -2;
    }
    __gquic_recovery_bytes(&prefix_len, 3, buf, size, &off);
    if ((size_t) prefix_len > size - off) {
        return -3;
    }
    __gquic_recovery_bytes(&prefix_len, 2, buf, size, &off);
    if ((size_t) prefix_len > size - off) {
        return -3;
    }
    if ((prefix_len = gquic_tls_encrypt_ext_msg_optional_deserialize(msg, buf + off, prefix_len)) != 0) {
        return -2;
    }
    off += prefix_len;

    return off;
}

static ssize_t gquic_tls_encrypt_ext_msg_optional_deserialize(gquic_tls_encrypt_ext_msg_t*msg, const void *buf, const size_t size) {
    u_int16_t opt_type = 0;
    size_t off = 0;
    gquic_tls_extension_t *field;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    while (off < size) {
        opt_type = 0;
        if (__gquic_recovery_bytes(&opt_type, 2, buf, size, &off) != 0) {
            return -2;
        }

        switch (opt_type) {

        case GQUIC_TLS_EXTENSION_ALPN:
            off += 2 + 2;
            if (__gquic_recovery_bytes(&msg->alpn_proto.size, 1, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_str(&msg->alpn_proto, msg->alpn_proto.size, buf, size, &off) != 0) {
                return -2;
            }
            break;

        default:
            if ((field = gquic_list_alloc(sizeof(gquic_tls_extension_t))) == NULL) {
                return -2;
            }
            field->type = 0;
            if (gquic_str_init(&field->data) != 0) {
                return -2;
            }
            if (__gquic_recovery_bytes(&field->type, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_bytes(&field->data.size, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_str(&field->data, field->data.size, buf, size, &off) != 0) {
                return -2;
            }
            if (gquic_list_insert_before(&msg->addition_exts, field) != 0) {
                return -2;
            }
            break;
        }
    }
    return off;
}

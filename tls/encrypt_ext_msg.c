#include "tls/encrypt_ext_msg.h"
#include "tls/common.h"
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
        gquic_str_reset(GQUIC_LIST_FIRST(&msg->addition_exts));
        gquic_list_release(GQUIC_LIST_FIRST(&msg->addition_exts));
    }
    return 0;
}

ssize_t gquic_tls_encrypt_ext_msg_size(const gquic_tls_encrypt_ext_msg_t *msg) {
    size_t ret = 0;
    if (msg == NULL) {
        return -1;
    }
    // encrypted extensions
    ret += 1;
    // payload len
    ret += 3;
    // payload len (x2)
    ret += 2;
    // alpn
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0) ret += 2 + 2 + 2 + 1 + GQUIC_STR_SIZE(&msg->alpn_proto);
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->addition_exts) ret += 2 + 2 + ext->data.size;
    return ret;
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
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS);

    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_ALPN);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str_full(buf, &off, &msg->alpn_proto, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->addition_exts) {
        __gquic_fill_2byte(buf, &off, ext->type);
        __gquic_fill_str_full(buf, &off, &ext->data, 2);
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
    if ((prefix_len = gquic_tls_encrypt_ext_msg_optional_deserialize(msg, buf + off, prefix_len)) < 0) {
        return -2;
    }
    off += prefix_len;

    return off;
}

static ssize_t gquic_tls_encrypt_ext_msg_optional_deserialize(gquic_tls_encrypt_ext_msg_t*msg, const void *buf, const size_t size) {
    u_int16_t opt_type = 0;
    size_t off = 0;
    size_t prefix_len = 0;
    size_t _;
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
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 1, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len;) {
                u_int8_t *alpn = gquic_list_alloc(sizeof(u_int8_t));
                if (alpn == NULL) {
                    return -2;
                }
                if (__gquic_recovery_bytes(alpn, 1, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(GQUIC_LIST_PAYLOAD(&msg->alpn_proto), alpn) != 0) {
                    return -2;
                }
            }
            break;

        default:
            if ((field = gquic_list_alloc(sizeof(gquic_tls_extension_t))) == NULL) {
                return -2;
            }
            field->type = opt_type;
            if (__gquic_recovery_str_full(&field->data, 2, buf, size, &off) != 0) {
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

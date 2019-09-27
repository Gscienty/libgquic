#include "tls/server_hello_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"

static ssize_t gquic_tls_server_hello_msg_payload_size(const gquic_tls_server_hello_msg_t *);
static ssize_t gquic_tls_server_hello_msg_optional_size(const gquic_tls_server_hello_msg_t *);

static ssize_t gquic_tls_server_hello_msg_payload_serialize(const gquic_tls_server_hello_msg_t *, void *, const size_t);
static ssize_t gquic_tls_server_hello_msg_optional_serialize(const gquic_tls_server_hello_msg_t *, void *, const size_t);

static ssize_t gquic_tls_server_hello_payload_deserialize(gquic_tls_server_hello_msg_t *, const void *, const size_t);
static ssize_t gquic_tls_server_hello_optional_deserialize(gquic_tls_server_hello_msg_t *, const void *, const size_t);

int gquic_tls_server_hello_msg_init(gquic_tls_server_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->vers = 0;
    gquic_str_init(&msg->random);
    gquic_str_init(&msg->sess_id);
    msg->cipher_suite = 0;
    msg->compression_method = 0;
    msg->next_proto_neg = 0;
    gquic_list_head_init(&msg->next_protos);
    msg->ocsp_stapling = 0;
    msg->ticket_supported = 0;
    msg->secure_regegotiation_supported = 0;
    gquic_str_init(&msg->secure_regegotation);
    gquic_str_init(&msg->alpn_proto);
    gquic_list_head_init(&msg->scts);
    msg->supported_version = 0;
    gquic_str_init(&msg->ser_share.data);
    msg->ser_share.group = 0;
    msg->selected_identity_persent = 0;
    msg->selected_identity = 0;
    gquic_str_init(&msg->cookie);
    msg->selected_group = 0;
    return 0;
}

int gquic_tls_server_hello_msg_reset(gquic_tls_server_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->random);
    gquic_str_reset(&msg->sess_id);
    gquic_str_reset(&msg->secure_regegotation);
    gquic_str_reset(&msg->alpn_proto);
    gquic_str_reset(&msg->ser_share.data);
    gquic_str_reset(&msg->cookie);
    while (!gquic_list_head_empty(&msg->next_protos)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->next_protos)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->next_protos)));
    }
    while (!gquic_list_head_empty(&msg->scts)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->scts)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->scts)));
    }
    return 0;
}

ssize_t gquic_tls_server_hello_msg_size(const gquic_tls_server_hello_msg_t *msg) {
    size_t ret = 0;
    if (msg == NULL) {
        return -1;
    }
    // server hello
    ret += 1;
    // payload
    ret += 3;
    ret += gquic_tls_server_hello_msg_payload_size(msg);
    return ret;
}

static ssize_t gquic_tls_server_hello_msg_payload_size(const gquic_tls_server_hello_msg_t *msg) {
    size_t ret = 0;
    if (msg == NULL) {
        return -1;
    }

    // ver
    ret += 2;
    // random
    ret += 32;
    // sess_id
    ret += 1 + msg->sess_id.size;
    // cipher_suite
    ret += 2;
    // compression_method
    ret += 1;
    // optional
    ret += 2 + gquic_tls_server_hello_msg_optional_size(msg);

    return ret;
}

static ssize_t gquic_tls_server_hello_msg_optional_size(const gquic_tls_server_hello_msg_t *msg) {
    size_t ret = 0;
    if (msg == NULL) {
        return -1;
    }
    // next_proto_neg
    if (msg->next_proto_neg) {
        ret += 2 + 2;
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->next_protos) ret += 1 + proto->size;
    }
    // ocsp_stapling
    if (msg->ocsp_stapling) ret += 2 + 2 + 1 + 2 + 2;
    // ticket_supported
    if (msg->ticket_supported) ret += 2 + 2;
    // secure_regegotiation_supported
    if (msg->secure_regegotiation_supported) ret += 2 + 2 + 1 + msg->secure_regegotation.size;
    // alpn
    if (msg->alpn_proto.size > 0) ret += 2 + 2 + 2 + 1 + msg->alpn_proto.size;
    // scts
    if (!gquic_list_head_empty(&msg->scts)) {
        ret += 2 + 2 + 2;
        gquic_str_t *sct;
        GQUIC_LIST_FOREACH(sct, &msg->scts) ret += 2 + sct->size;
    }
    // supported_version
    if (msg->supported_version) ret += 2 + 2 + 2;
    // server_share
    if (msg->ser_share.group) ret += 2 + 2 + 2 + 2 + msg->ser_share.data.size;
    // selected_identity_persent
    if (msg->selected_identity_persent) ret += 2 + 2 + 2;
    // cookie
    if (msg->cookie.size > 0) ret += 2 + 2 + 2 + msg->cookie.size;
    // selected_group
    if (msg->selected_group) ret += 2 + 2 + 2;
    return ret;
}

ssize_t gquic_tls_server_hello_msg_serialize(const gquic_tls_server_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_server_hello_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    // server_hello
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO);

    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    if ((ret = gquic_tls_server_hello_msg_payload_serialize(msg, buf + off, size - off)) <= 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

static ssize_t gquic_tls_server_hello_msg_payload_serialize(const gquic_tls_server_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_server_hello_msg_payload_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // vers
    __gquic_fill_2byte(buf, &off, msg->vers);

    // random
    if (msg->random.size != 32) {
        return -3;
    }
    __gquic_fill_str(buf, &off, &msg->random);

    // cipher_suite
    __gquic_fill_2byte(buf, &off, msg->cipher_suite);

    // compression_method
    __gquic_fill_1byte(buf, &off, msg->compression_method);

    // optional prefix len
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if ((ret = gquic_tls_server_hello_msg_optional_serialize(msg, buf + off, size - off)) < 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);

    return off;
}

static ssize_t gquic_tls_server_hello_msg_optional_serialize(const gquic_tls_server_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_server_hello_msg_payload_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // next_proto_neg
    if (msg->next_proto_neg) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->next_protos) {
            __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
            __gquic_fill_str(buf, &off, proto);
            __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        }
    }

    // ocsp_stapling
    if (msg->ocsp_stapling) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
        __gquic_fill_2byte(buf, &off, 0);
    }

    // ticket_supported
    if (msg->ticket_supported) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SESS_TICKET);
        __gquic_fill_2byte(buf, &off, 0);
    }

    // secure_regegotiation_supported
    if (msg->secure_regegotiation_supported) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        __gquic_fill_str(buf, &off, &msg->secure_regegotation);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // alpn
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

    // scts
    if (!gquic_list_head_empty(&msg->scts)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SCT);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *sct;
        GQUIC_LIST_FOREACH(sct, &msg->scts) {
            __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
            __gquic_fill_str(buf, &off, sct);
            __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // supported_version
    if (msg->supported_version) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_2byte(buf, &off, msg->supported_version);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // ser_share
    if (msg->ser_share.group) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_KEY_SHARE);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_2byte(buf, &off, msg->ser_share.group);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str(buf, &off, &msg->ser_share.data);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // selected_identity_persent
    if (msg->selected_identity_persent) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_PRE_SHARED_KEY);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_2byte(buf, &off, msg->selected_identity);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // cookie
    if (msg->cookie.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_COOKIE);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str(buf, &off, &msg->cookie);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // selected_group
    if (msg->selected_group) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_KEY_SHARE);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_2byte(buf, &off, msg->selected_group);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    return off;
}

ssize_t gquic_tls_server_hello_msg_deserialize(gquic_tls_server_hello_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
        return -2;
    }
    __gquic_recovery_bytes(&ret, 3, buf, size, &off);
    if ((size_t) ret > size - off) {
        return -3;
    }
    if ((ret = gquic_tls_server_hello_payload_deserialize(msg, buf + off, size - off)) < 0) {
        return -3;
    }
    off += ret;
    return off;
}

static ssize_t gquic_tls_server_hello_payload_deserialize(gquic_tls_server_hello_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    size_t prefix_len = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }

    // vers
    if (__gquic_recovery_bytes(&msg->vers, 2, buf, size, &off) != 0) {
        return -2;
    }

    // random
    if (__gquic_recovery_str(&msg->random, 32, buf, size, &off) != 0) {
        return -2;
    }

    // sess_id
    prefix_len = 0;
    if (__gquic_recovery_bytes(&msg->sess_id.size, 1, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str(&msg->sess_id, msg->sess_id.size, buf, size, &off) != 0) {
        return -2;
    }

    // cipher_suite
    if (__gquic_recovery_bytes(&msg->cipher_suite, 2, buf, size, &off) != 0) {
        return -2;
    }

    // compression_method
    if (__gquic_recovery_bytes(&msg->compression_method, 1, buf, size, &off) != 0) {
        return -2;
    }

    // optional prefix len
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
        return -2;
    }
    if (prefix_len > size) {
        return -2;
    }
    if (gquic_tls_server_hello_optional_deserialize(msg, buf + off, prefix_len) != 0) {
        return -2;
    }
    off += prefix_len;

    return off;
}

static ssize_t gquic_tls_server_hello_optional_deserialize(gquic_tls_server_hello_msg_t *msg, const void *buf, const size_t size) {
    u_int16_t opt_type = 0;
    size_t off = 0;
    size_t prefix_len = 0;
    size_t _;
    void *field;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    while (off < size) {
        opt_type = 0;
        if (__gquic_recovery_bytes(&opt_type, 2, buf, size, &off) != 0) {
            return -2;
        }

        switch (opt_type) {
            
        case GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG:
            msg->next_proto_neg = 1;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len; _++) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    return -2;
                }
                if (__gquic_recovery_bytes(&((gquic_str_t *) field)->size, 1, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_str(field, ((gquic_str_t *) field)->size, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->next_protos, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            msg->ocsp_stapling = 1;
            off += 2;
            break;

        case GQUIC_TLS_EXTENSION_SESS_TICKET:
            msg->ticket_supported = 1;
            off += 2;
            break;

        case GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO:
            off += 2;
            if (__gquic_recovery_bytes(&msg->secure_regegotation.size, 1, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_bytes(&msg->secure_regegotation, msg->secure_regegotation.size, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_ALPN:
            off += 2 + 2;
            if (__gquic_recovery_bytes(&msg->alpn_proto.size, 1, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_bytes(&msg->alpn_proto, msg->alpn_proto.size, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len; _++) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    return -2;
                }
                if (__gquic_recovery_bytes(&((gquic_str_t *) field)->size, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_str(field, ((gquic_str_t *) field)->size, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->scts, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS:
            off += 2;
            if (__gquic_recovery_bytes(&msg->supported_version, 2, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_KEY_SHARE:
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (prefix_len == 2) {
                if (__gquic_recovery_bytes(&msg->selected_group, 2, buf, size, &off) != 0) {
                    return -2;
                }
            }
            else {
                if (__gquic_recovery_bytes(&msg->ser_share.group, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_bytes(&msg->ser_share.data.size, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_str(&msg->ser_share.data, msg->ser_share.data.size, buf, size, &off) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_PRE_SHARED_KEY:
            off += 2;
            if (__gquic_recovery_bytes(&msg->selected_identity, 2, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_COOKIE:
            off += 2;
            if (__gquic_recovery_bytes(&msg->cookie.size, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (__gquic_recovery_str(&msg->cookie, msg->cookie.size, buf, size, &off) != 0) {
                return -2;
            }
            break;
        }
    }

    return off;
}

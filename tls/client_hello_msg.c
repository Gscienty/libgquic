#include "tls/client_hello_msg.h"
#include "tls/config.h"
#include "util/big_endian.h"
#include <string.h>

static ssize_t gquic_tls_client_hello_payload_size(const gquic_tls_client_hello_msg_t *);
static ssize_t gquic_tls_client_hello_optional_size(const gquic_tls_client_hello_msg_t *);

static ssize_t gquic_tls_client_hello_payload_serialize(const gquic_tls_client_hello_msg_t *, void *, const size_t);
static ssize_t gquic_tls_client_hello_optional_serialize(const gquic_tls_client_hello_msg_t *, void *, const size_t);

static inline void __gquic_stack_push(gquic_list_t *, const size_t);
static inline size_t __gquic_stack_pop(gquic_list_t *);
static inline void __gquic_fill_prefix_len(gquic_list_t *, void *, const size_t, const size_t);
static inline void __gquic_store_prefix_len(gquic_list_t *, size_t *, const size_t);
static inline void __gquic_fill_4byte(void *, size_t *, const u_int32_t);
static inline void __gquic_fill_2byte(void *, size_t *, const u_int16_t);
static inline void __gquic_fill_1byte(void *, size_t *, const u_int8_t);

int gquic_tls_client_hello_msg_init(gquic_tls_client_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->vers = 0;
    gquic_str_init(&msg->random);
    gquic_str_init(&msg->sess_id);
    gquic_list_head_init(&msg->cipher_suites);
    gquic_str_init(&msg->compression_methods);
    msg->next_proto_neg = 0;
    gquic_str_init(&msg->ser_name);
    msg->ocsp_stapling = 0;
    gquic_list_head_init(&msg->supported_curves);
    gquic_str_init(&msg->supported_points);
    msg->ticket_supported = 0;
    gquic_str_init(&msg->sess_ticket);
    gquic_list_head_init(&msg->supported_sign_algos);
    gquic_list_head_init(&msg->supported_sign_algos_cert);
    msg->secure_regegotiation_supported = 0;
    gquic_list_head_init(&msg->alpn_protos);
    msg->scts = 0;
    gquic_list_head_init(&msg->supported_versions);
    gquic_str_init(&msg->cookie);
    gquic_list_head_init(&msg->key_shares);
    msg->early_data = 0;
    gquic_str_init(&msg->psk_modes);
    gquic_list_head_init(&msg->psk_identities);
    gquic_list_head_init(&msg->psk_binders);
    gquic_list_head_init(&msg->extensions);
    return 0;
}

ssize_t gquic_tls_client_hello_msg_size(const gquic_tls_client_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    size_t ret = 0;

    // client hello
    ret += 1;
    // payload
    ret += 3;
    ret += gquic_tls_client_hello_payload_size(msg);
    return ret;
}

ssize_t gquic_tls_client_hello_payload_size(const gquic_tls_client_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    void *_;
    size_t ret = 0;

    // vers
    ret += 2;
    // random
    ret += 32;
    // sess_id
    ret += 1 + msg->sess_id.size;
    // cipher_suites
    ret += 2;
    GQUIC_LIST_FOREACH(_, &msg->cipher_suites) ret += 2;
    // compression_methods
    ret += 1 + msg->compression_methods.size;
    // optional
    ret += 2 + gquic_tls_client_hello_optional_size(msg);

    return ret;
}

ssize_t gquic_tls_client_hello_msg_serialize(const gquic_tls_client_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    // client_hello
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO);

    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    if ((ret = gquic_tls_client_hello_payload_serialize(msg, buf + off, size - off)) <= 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

static ssize_t gquic_tls_client_hello_optional_size(const gquic_tls_client_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    void *_;
    size_t ret = 0;

    // next_proto_neg
    if (msg->next_proto_neg) ret += 2 + 2;
    // ser_name
    if (msg->ser_name.size != 0) ret += 2 + 2 + 2 + 1 + 2 + msg->ser_name.size;
    // ocsp_stapling
    if (msg->ocsp_stapling) ret += 2 + 2 + 1 + 2 + 2;
    // supported curves
    if (!gquic_list_head_empty(&msg->supported_curves)) {
        ret += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &msg->supported_curves) ret += 2;
    }
    // supported points
    if (msg->supported_points.size != 0) ret += 2 + 2 + 1 + msg->supported_points.size;
    // sess_ticket
    if (msg->sess_ticket.size != 0) ret += 2 + 2 + msg->sess_ticket.size;
    // supported_sign_algos
    if (!gquic_list_head_empty(&msg->supported_sign_algos)) {
        ret += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &msg->supported_sign_algos) ret += 2;
    }
    // supported_sign_algos_cert
    if (!gquic_list_head_empty(&msg->supported_sign_algos_cert)) {
        ret += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &msg->supported_sign_algos_cert) ret += 2;
    }
    // secure_renegotiation_supported
    if (msg->secure_regegotiation_supported) ret += 2 + 2 + 1 + msg->secure_regegotation.size;
    // alpn_protos
    if (!gquic_list_head_empty(&msg->alpn_protos)) {
        ret += 2 + 2 + 2;
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->alpn_protos) ret += 1 + proto->size;
    }
    // scts
    if (msg->scts) ret += 2 + 2;
    // supported version
    if (!gquic_list_head_empty(&msg->supported_versions)) {
        ret += 2 + 2 + 1;
        GQUIC_LIST_FOREACH(_, &msg->supported_versions) ret += 2;
    }
    // cookie
    if (msg->cookie.size > 0) {
        ret += 2 + 2 + 2 + msg->cookie.size;
    }
    // key_shares
    if (!gquic_list_head_empty(&msg->key_shares)) {
        gquic_tls_key_share_t *ks;
        ret += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(ks, &msg->key_shares) ret += 2 + 2 + ks->data.size;
    }
    // early_data
    if (msg->early_data) {
        ret += 2 + 2;
    }
    // psk_modes
    if (msg->psk_modes.size > 0) {
        ret += 2 + 2 + 1 + msg->psk_modes.size;
    }
    // extensions
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->extensions) ret += 2 + 2 + ext->data.size;
    // psk_identities
    if (!gquic_list_head_empty(&msg->psk_identities)) {
        gquic_tls_psk_identity_t *psk;
        gquic_str_t *binder;
        ret += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(psk, &msg->psk_identities) ret += 2 + psk->label.size + 4;
        ret += 2;
        GQUIC_LIST_FOREACH(binder, &msg->psk_binders) ret += 1 + binder->size;
    }

    return ret;
}

static ssize_t gquic_tls_client_hello_payload_serialize(const gquic_tls_client_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_payload_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // vers
    __gquic_fill_2byte(buf, &off, msg->vers);

    // random
    if (msg->random.size != 32) {
        return -3;
    }
    memcpy(buf + off, msg->random.val, msg->random.size);
    off += msg->random.size;

    // sess_id
    __gquic_fill_1byte(buf, &off, msg->sess_id.size);
    memcpy(buf + off, msg->sess_id.val, msg->sess_id.size);
    off += msg->sess_id.size;

    // cipher_suites
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    u_int16_t *suite;
    GQUIC_LIST_FOREACH(suite, &msg->cipher_suites) __gquic_fill_2byte(buf, &off, *suite);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);

    // compression_methods
    __gquic_fill_1byte(buf, &off, msg->compression_methods.size);
    memcpy(buf + off, msg->compression_methods.val, msg->compression_methods.size);
    off += msg->compression_methods.size;

    // optional prefix len
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if ((ret = gquic_tls_client_hello_optional_serialize(msg, buf + off, size - off)) < 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);

    return off;
}

static inline void __gquic_stack_push(gquic_list_t *stack, const size_t val) {
    gquic_list_insert_after(stack, gquic_list_alloc(sizeof(size_t)));
    *(size_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(stack)) = val;
}

static inline size_t __gquic_stack_pop(gquic_list_t *stack) {
    size_t ret = *(size_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(stack));
    gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(stack)));
    return ret;
}

static inline void __gquic_fill_prefix_len(gquic_list_t *stack, void *buf, const size_t off, const size_t len) {
    size_t prefix_len_off = __gquic_stack_pop(stack);
    size_t prefix_len = off - 2 - prefix_len_off;
    gquic_big_endian_transfer(buf + prefix_len_off, &prefix_len, len);
}

static inline void __gquic_store_prefix_len(gquic_list_t *stack, size_t *off, const size_t len) {
    __gquic_stack_push(stack, *off);
    *off += len;
}

static inline void __gquic_fill_4byte(void *buf, size_t *off, const u_int32_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 4);
    *off += 4;
}

static inline void __gquic_fill_2byte(void *buf, size_t *off, const u_int16_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 2);
    *off += 2;
}

static inline void __gquic_fill_1byte(void *buf, size_t *off, const u_int8_t val) {
    gquic_big_endian_transfer(buf + *off, &val, 1);
    *off += 1;
}

static ssize_t gquic_tls_client_hello_optional_serialize(const gquic_tls_client_hello_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    int _lazy = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_optional_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // next proto msg
    if (msg->next_proto_neg) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG);
        __gquic_fill_2byte(buf, &off, 0);
    }

    // ser_name
    if (msg->ser_name.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SERVER_NAME);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_1byte(buf, &off, 0);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        memcpy(buf + off, msg->ser_name.val, msg->ser_name.size);
        off += msg->ser_name.size;

        for (_lazy = 0; _lazy < 3; _lazy++) {
            __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        }
    }

    // ocsp_stapling
    if (msg->ocsp_stapling) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_1byte(buf, &off, 1);
        __gquic_fill_2byte(buf, &off, 0);
        __gquic_fill_2byte(buf, &off, 0);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // supported_curves
    if (!gquic_list_head_empty(&msg->supported_curves)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SUPPORTED_CURVES);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        u_int16_t *curve;
        GQUIC_LIST_FOREACH(curve, &msg->supported_curves) __gquic_fill_2byte(buf, &off, *curve);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // supported_points
    if (msg->supported_points.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SUPPORTED_POINTS);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        memcpy(buf + off, msg->supported_points.val, msg->supported_points.size);
        off += msg->supported_points.size;
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // ticket_support
    if (msg->ticket_supported) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SESS_TICKET);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        memcpy(buf + off, msg->sess_ticket.val, msg->sess_ticket.size);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // supported_sign_algos
    if (!gquic_list_head_empty(&msg->supported_sign_algos)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SIGN_ALGOS);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &msg->supported_sign_algos) __gquic_fill_2byte(buf, &off, *sig);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // supported_sign_algos_cert
    if (!gquic_list_head_empty(&msg->supported_sign_algos_cert)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &msg->supported_sign_algos_cert) __gquic_fill_2byte(buf, &off, *sig);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // secure_regegotation
    if (msg->secure_regegotation.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        memcpy(buf + off, msg->secure_regegotation.val, msg->secure_regegotation.size);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // alpn
    if (!gquic_list_head_empty(&msg->alpn_protos)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_ALPN);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->alpn_protos) {
            __gquic_fill_1byte(buf, &off, proto->size);
            memcpy(buf + off, proto->val, proto->size);
            off += proto->size;
        }
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // scts
    if (msg->scts) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SCT);
        __gquic_fill_2byte(buf, &off, 0);
    }

    // supported_versions
    if (!gquic_list_head_empty(&msg->supported_versions)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        u_int16_t *vers;
        GQUIC_LIST_FOREACH(vers, &msg->supported_versions) __gquic_fill_2byte(buf, &off, *vers);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // cookie
    if (msg->cookie.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_COOKIE);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        memcpy(buf + off, msg->cookie.val, msg->cookie.size);
        off += msg->cookie.size;
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // key_shares
    if (!gquic_list_head_empty(&msg->key_shares)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_KEY_SHARE);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_tls_key_share_t *ks;
        GQUIC_LIST_FOREACH(ks, &msg->key_shares) {
            __gquic_fill_2byte(buf, &off, ks->group);
            __gquic_fill_2byte(buf, &off, ks->data.size);
            memcpy(buf + off, ks->data.val, ks->data.size);
            off += ks->data.size;
        }
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // early_data
    if (msg->early_data) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_EARLY_DATA);
        __gquic_fill_2byte(buf, &off, 0);
    }

    // psk_modes
    if (msg->psk_modes.size > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_PSK_MODES);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 1);
        memcpy(buf + off, msg->psk_modes.val, msg->psk_modes.size);
        off += msg->psk_modes.size;
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // exts
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->extensions) {
        __gquic_fill_2byte(buf, &off, ext->type);
        memcpy(buf + off, ext->data.val, ext->data.size);
        off += ext->data.size;
    }

    // psk_identities
    if (!gquic_list_head_empty(&msg->psk_identities)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_PRE_SHARED_KEY);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_tls_psk_identity_t *psk;
        GQUIC_LIST_FOREACH(psk, &msg->psk_identities) {
            __gquic_fill_2byte(buf, &off, psk->label.size);
            memcpy(buf + off, psk->label.val, psk->label.size);
            off += psk->label.size;
            __gquic_fill_4byte(buf, &off, psk->obfuscated_tickett_age);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *binder;
        GQUIC_LIST_FOREACH(binder, &msg->psk_binders) {
            __gquic_fill_1byte(buf, &off, binder->size);
            memcpy(buf + off, binder->val, binder->size);
            off += binder->size;
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    return off;
}


#include "tls/client_hello_msg.h"
#include "tls/config.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "util/big_endian.h"
#include <string.h>

static ssize_t gquic_tls_client_hello_payload_size(const gquic_tls_client_hello_msg_t *);
static ssize_t gquic_tls_client_hello_optional_size(const gquic_tls_client_hello_msg_t *);

static ssize_t gquic_tls_client_hello_payload_serialize(const gquic_tls_client_hello_msg_t *, void *, const size_t);
static ssize_t gquic_tls_client_hello_optional_serialize(const gquic_tls_client_hello_msg_t *, void *, const size_t);

static ssize_t gquic_tls_client_hello_payload_deserialize(gquic_tls_client_hello_msg_t *, const void *, const size_t);
static ssize_t gquic_tls_client_hello_optional_deserialize(gquic_tls_client_hello_msg_t *, const void *, const size_t);

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
    gquic_str_init(&msg->secure_regegotation);
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

int gquic_tls_client_hello_msg_reset(gquic_tls_client_hello_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }

    gquic_str_reset(&msg->random);
    gquic_str_reset(&msg->sess_id);
    while (!gquic_list_head_empty(&msg->cipher_suites)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->cipher_suites)));
    }
    gquic_str_reset(&msg->compression_methods);
    gquic_str_reset(&msg->ser_name);
    while (!gquic_list_head_empty(&msg->supported_curves)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_curves)));
    }
    gquic_str_reset(&msg->supported_points);
    gquic_str_reset(&msg->sess_ticket);
    while (!gquic_list_head_empty(&msg->supported_sign_algos)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_sign_algos)));
    }
    while (!gquic_list_head_empty(&msg->supported_sign_algos_cert)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_sign_algos_cert)));
    }
    gquic_str_reset(&msg->secure_regegotation);
    while (!gquic_list_head_empty(&msg->alpn_protos)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->alpn_protos)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->alpn_protos)));
    }
    while (!gquic_list_head_empty(&msg->supported_versions)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_versions)));
    }
    while (!gquic_list_head_empty(&msg->key_shares)) {
        gquic_str_reset(&((gquic_tls_key_share_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->alpn_protos)))->data);
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->key_shares)));
    }
    gquic_str_reset(&msg->psk_modes);
    while (!gquic_list_head_empty(&msg->extensions)) {
        gquic_str_reset(&((gquic_tls_extension_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->extensions)))->data);
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->extensions)));
    }
    while (!gquic_list_head_empty(&msg->psk_identities)) {
        gquic_str_reset(&((gquic_tls_psk_identity_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->psk_identities)))->label);
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->psk_identities)));
    }
    while (!gquic_list_head_empty(&msg->psk_binders)) {
        gquic_str_reset(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->psk_binders)));
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->psk_binders)));
    }
    gquic_tls_client_hello_msg_init(msg);
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

ssize_t gquic_tls_client_hello_msg_deserialize(gquic_tls_client_hello_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t ret = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        return -2;
    }

    __gquic_recovery_bytes(&ret, 3, buf, size, &off);
    if ((size_t) ret > size - off) {
        return -3;
    }
    if ((ret = gquic_tls_client_hello_payload_deserialize(msg, buf + off, ret)) <= 0) {
        return -3;
    }
    off += ret;
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
    if (msg->ticket_supported) ret += 2 + 2 + msg->sess_ticket.size;
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
    __gquic_fill_str(buf, &off, &msg->random);

    // sess_id
    __gquic_fill_str_full(buf, &off, &msg->sess_id, 1);

    // cipher_suites
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    u_int16_t *suite;
    GQUIC_LIST_FOREACH(suite, &msg->cipher_suites) __gquic_fill_2byte(buf, &off, *suite);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);

    // compression_methods
    __gquic_fill_str_full(buf, &off, &msg->compression_methods, 1);

    // optional prefix len
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if ((ret = gquic_tls_client_hello_optional_serialize(msg, buf + off, size - off)) < 0) {
        return -3;
    }
    off += ret;
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);

    return off;
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
        __gquic_fill_str_full(buf, &off, &msg->ser_name, 2);

        for (_lazy = 0; _lazy < 2; _lazy++) {
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
        __gquic_fill_str_full(buf, &off, &msg->supported_points, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // ticket_support
    if (msg->ticket_supported) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SESS_TICKET);
        __gquic_fill_str_full(buf, &off, &msg->sess_ticket, 2);
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
    if (msg->secure_regegotiation_supported) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str_full(buf, &off, &msg->secure_regegotation, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // alpn
    if (!gquic_list_head_empty(&msg->alpn_protos)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_ALPN);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->alpn_protos) {
            __gquic_fill_str_full(buf, &off, proto, 1);
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
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_str_full(buf, &off, &msg->cookie, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // key_shares
    if (!gquic_list_head_empty(&msg->key_shares)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_KEY_SHARE);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_tls_key_share_t *ks;
        GQUIC_LIST_FOREACH(ks, &msg->key_shares) {
            __gquic_fill_2byte(buf, &off, ks->group);
            __gquic_fill_str_full(buf, &off, &ks->data, 2);
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
        __gquic_fill_str_full(buf, &off, &msg->psk_modes, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    // exts
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->extensions) {
        __gquic_fill_2byte(buf, &off, ext->type);
        __gquic_fill_str_full(buf, &off, &ext->data, 2);
    }

    // psk_identities
    if (!gquic_list_head_empty(&msg->psk_identities)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_PRE_SHARED_KEY);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_tls_psk_identity_t *psk;
        GQUIC_LIST_FOREACH(psk, &msg->psk_identities) {
            __gquic_fill_str_full(buf, &off, &psk->label, 2);
            __gquic_fill_4byte(buf, &off, psk->obfuscated_ticket_age);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *binder;
        GQUIC_LIST_FOREACH(binder, &msg->psk_binders) {
            __gquic_fill_str_full(buf, &off, binder, 1);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    return off;
}

static ssize_t gquic_tls_client_hello_payload_deserialize(gquic_tls_client_hello_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    size_t prefix_len = 0;
    size_t _;
    void *field;
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
    if (__gquic_recovery_str_full(&msg->sess_id, 1, buf, size, &off) != 0) {
        return -2;
    }

    // cipher_suites
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
        if (gquic_list_insert_before(&msg->cipher_suites, field) != 0) {
            return -2;
        }
    }

    // compression_methods
    if (__gquic_recovery_str_full(&msg->compression_methods, 1, buf, size, &off) != 0) {
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
    if (gquic_tls_client_hello_optional_deserialize(msg, buf + off, prefix_len) < 0) {
        return -2;
    }
    off += prefix_len;

    return off;
}

static ssize_t gquic_tls_client_hello_optional_deserialize(gquic_tls_client_hello_msg_t *msg, const void *buf, const size_t size) {
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
            off += 2;
            break;

        case GQUIC_TLS_EXTENSION_SERVER_NAME:
            off += 2 + 2 + 1;
            if (__gquic_recovery_str_full(&msg->ser_name, 2, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            msg->ocsp_stapling = 1;
            off += 2 + 1 + 2 + 2;
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_CURVES:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len;){
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    return -2;
                }
                *(u_int16_t *) field = 0;
                if (__gquic_recovery_bytes(field, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->supported_curves, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_POINTS:
            off += 2;
            if (__gquic_recovery_str_full(&msg->supported_points, 1, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_SESS_TICKET:
            msg->ticket_supported = 1;
            if (__gquic_recovery_str_full(&msg->sess_ticket, 2, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS:
            off += 2;
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
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT:
            off += 2;
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
                if (gquic_list_insert_before(&msg->supported_sign_algos_cert, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO:
            off += 2;
            msg->secure_regegotiation_supported = 1;
            if (__gquic_recovery_str_full(&msg->secure_regegotation, 1, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_ALPN:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    return -2;
                }
                ((gquic_str_t *) field)->size = 0;
                if (__gquic_recovery_str_full(field, 1, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->alpn_protos, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            off += 2;
            msg->scts = 1;
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 1, buf, size, &off) != 0) {
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
                if (gquic_list_insert_before(&msg->supported_versions, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_COOKIE:
            off += 2;
            if (__gquic_recovery_str_full(&msg->cookie, 2, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_KEY_SHARE:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_tls_key_share_t))) == NULL) {
                    return -2;
                }
                ((gquic_tls_key_share_t *) field)->group = 0;
                if (__gquic_recovery_bytes(&((gquic_tls_key_share_t *) field)->group, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_str_full(&((gquic_tls_key_share_t *) field)->data, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->key_shares, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_EARLY_DATA:
            off += 2;
            msg->early_data = 1;
            break;

        case GQUIC_TLS_EXTENSION_PSK_MODES:
            off += 2;
            if (__gquic_recovery_str_full(&msg->psk_modes, 1, buf, size, &off) != 0) {
                return -2;
            }
            break;

        case GQUIC_TLS_EXTENSION_PRE_SHARED_KEY:
            off += 2;
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
                return -2;
            }
            for (_ = off; off - _ < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_tls_psk_identity_t))) == NULL) {
                    return -2;
                }
                if (__gquic_recovery_str_full(&((gquic_tls_psk_identity_t *) field)->label, 2, buf, size, &off) != 0) {
                    return -2;
                }
                if (__gquic_recovery_bytes(&((gquic_tls_psk_identity_t *) field)->obfuscated_ticket_age, 4, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->psk_identities, field) != 0) {
                    return -2;
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
                if (__gquic_recovery_str_full(field, 1, buf, size, &off) != 0) {
                    return -2;
                }
                if (gquic_list_insert_before(&msg->psk_binders, field) != 0) {
                    return -2;
                }
            }
            break;

        default:
            if ((field = gquic_list_alloc(sizeof(gquic_tls_extension_t))) == NULL) {
                return -2;
            }
            ((gquic_tls_extension_t *) field)->type = opt_type;
            if (__gquic_recovery_str_full(&((gquic_tls_extension_t *) field)->data, 2, buf, size, &off) != 0) {
                return -2;
            }
            if (gquic_list_insert_before(&msg->extensions, field) != 0) {
                return -2;
            }
        }
    }

    return off;
}

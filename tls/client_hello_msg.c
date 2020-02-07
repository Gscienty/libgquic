#include "tls/client_hello_msg.h"
#include "tls/common.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/meta.h"
#include "util/big_endian.h"
#include <string.h>

static ssize_t gquic_tls_client_hello_payload_size(const gquic_tls_client_hello_msg_t *);
static ssize_t gquic_tls_client_hello_optional_size(const gquic_tls_client_hello_msg_t *);

static int gquic_tls_client_hello_payload_serialize(const gquic_tls_client_hello_msg_t *, gquic_writer_str_t *const);
static int gquic_tls_client_hello_optional_serialize(const gquic_tls_client_hello_msg_t *, gquic_writer_str_t *const);

static int gquic_tls_client_hello_payload_deserialize(gquic_tls_client_hello_msg_t *, gquic_reader_str_t *const);
static int gquic_tls_client_hello_optional_deserialize(gquic_tls_client_hello_msg_t *, gquic_reader_str_t *const);

static int gquic_tls_client_hello_msg_init(void *const msg);
static int gquic_tls_client_hello_msg_dtor(void *const msg);
static ssize_t gquic_tls_client_hello_msg_size(const void *const msg);
static int gquic_tls_client_hello_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_client_hello_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_client_hello_msg_t *gquic_tls_client_hello_msg_alloc() {
    gquic_tls_client_hello_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_client_hello_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_client_hello_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_client_hello_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_client_hello_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_client_hello_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_client_hello_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO;

    return msg;
}

static int gquic_tls_client_hello_msg_init(void *const msg) {
    gquic_tls_client_hello_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    spec->vers = 0;
    gquic_str_init(&spec->random);
    gquic_str_init(&spec->sess_id);
    gquic_list_head_init(&spec->cipher_suites);
    gquic_str_init(&spec->compression_methods);
    spec->next_proto_neg = 0;
    gquic_str_init(&spec->ser_name);
    spec->ocsp_stapling = 0;
    gquic_list_head_init(&spec->supported_curves);
    gquic_str_init(&spec->supported_points);
    spec->ticket_supported = 0;
    gquic_str_init(&spec->sess_ticket);
    gquic_list_head_init(&spec->supported_sign_algos);
    gquic_list_head_init(&spec->supported_sign_algos_cert);
    spec->secure_regegotiation_supported = 0;
    gquic_str_init(&spec->secure_regegotation);
    gquic_list_head_init(&spec->alpn_protos);
    spec->scts = 0;
    gquic_list_head_init(&spec->supported_versions);
    gquic_str_init(&spec->cookie);
    gquic_list_head_init(&spec->key_shares);
    spec->early_data = 0;
    gquic_str_init(&spec->psk_modes);
    gquic_list_head_init(&spec->psk_identities);
    gquic_list_head_init(&spec->psk_binders);
    gquic_list_head_init(&spec->extensions);
    return 0;
}

static int gquic_tls_client_hello_msg_dtor(void *const msg) {
    gquic_tls_client_hello_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }

    gquic_str_reset(&spec->random);
    gquic_str_reset(&spec->sess_id);
    while (!gquic_list_head_empty(&spec->cipher_suites)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->cipher_suites));
    }
    gquic_str_reset(&spec->compression_methods);
    gquic_str_reset(&spec->ser_name);
    while (!gquic_list_head_empty(&spec->supported_curves)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_curves));
    }
    gquic_str_reset(&spec->supported_points);
    gquic_str_reset(&spec->sess_ticket);
    while (!gquic_list_head_empty(&spec->supported_sign_algos)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_sign_algos));
    }
    while (!gquic_list_head_empty(&spec->supported_sign_algos_cert)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_sign_algos_cert));
    }
    gquic_str_reset(&spec->secure_regegotation);
    while (!gquic_list_head_empty(&spec->alpn_protos)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&spec->alpn_protos));
        gquic_list_release(GQUIC_LIST_FIRST(&spec->alpn_protos));
    }
    while (!gquic_list_head_empty(&spec->supported_versions)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_versions));
    }
    while (!gquic_list_head_empty(&spec->key_shares)) {
        gquic_str_reset(&((gquic_tls_key_share_t *) GQUIC_LIST_FIRST(&spec->key_shares))->data);
        gquic_list_release(GQUIC_LIST_FIRST(&spec->key_shares));
    }
    gquic_str_reset(&spec->psk_modes);
    while (!gquic_list_head_empty(&spec->extensions)) {
        gquic_str_reset(&((gquic_tls_extension_t *) GQUIC_LIST_FIRST(&spec->extensions))->data);
        gquic_list_release(GQUIC_LIST_FIRST(&spec->extensions));
    }
    while (!gquic_list_head_empty(&spec->psk_identities)) {
        gquic_str_reset(&((gquic_tls_psk_identity_t *) GQUIC_LIST_FIRST(&spec->psk_identities))->label);
        gquic_list_release(GQUIC_LIST_FIRST(&spec->psk_identities));
    }
    while (!gquic_list_head_empty(&spec->psk_binders)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&spec->psk_binders));
        gquic_list_release(GQUIC_LIST_FIRST(&spec->psk_binders));
    }
    gquic_tls_client_hello_msg_init(spec);
    return 0;
}

static ssize_t gquic_tls_client_hello_msg_size(const void *const msg) {
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

ssize_t gquic_tls_client_hello_msg_size_without_binders(gquic_tls_client_hello_msg_t *msg) {
    ssize_t ret = gquic_tls_client_hello_msg_size(msg);
    if (ret < 0) {
        return -1;
    }
    ret -= 2;
    gquic_str_t *binder;
    GQUIC_LIST_FOREACH(binder, &msg->psk_binders) {
        ret -= 1 + GQUIC_STR_SIZE(binder);
    }
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

static int gquic_tls_client_hello_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    ssize_t ret;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    // client_hello
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO);

    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    if ((ret = gquic_tls_client_hello_payload_serialize(msg, writer)) != 0) {
        return -3;
    }
    __gquic_fill_prefix_len(&prefix_len_stack, writer);
    return 0;
}

static int gquic_tls_client_hello_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    ssize_t ret = 0;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        return -2;
    }

    __gquic_recovery_bytes(&ret, 3, reader);
    if ((size_t) ret > GQUIC_STR_SIZE(reader)) {
        return -3;
    }
    if ((ret = gquic_tls_client_hello_payload_deserialize(msg, reader)) != 0) {
        return -4;
    }
    return 0;
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

static int gquic_tls_client_hello_payload_serialize(const gquic_tls_client_hello_msg_t *msg, gquic_writer_str_t *const writer) {
    ssize_t ret = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_payload_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // vers
    gquic_big_endian_writer_2byte(writer, msg->vers);

    // random
    if (msg->random.size != 32) {
        return -3;
    }
    gquic_writer_str_write(writer, &msg->random);

    // sess_id
    __gquic_fill_str(writer, &msg->sess_id, 1);

    // cipher_suites
    __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
    u_int16_t *suite;
    GQUIC_LIST_FOREACH(suite, &msg->cipher_suites) gquic_big_endian_writer_2byte(writer, *suite);
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    // compression_methods
    __gquic_fill_str(writer, &msg->compression_methods, 1);

    // optional prefix len
    __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
    if ((ret = gquic_tls_client_hello_optional_serialize(msg, writer)) < 0) {
        return -3;
    }
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    return 0;
}


static int gquic_tls_client_hello_optional_serialize(const gquic_tls_client_hello_msg_t *msg, gquic_writer_str_t *const writer) {
    int _lazy = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_hello_optional_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    // next proto msg
    if (msg->next_proto_neg) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG);
        gquic_big_endian_writer_2byte(writer, 0);
    }

    // ser_name
    if (msg->ser_name.size > 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SERVER_NAME);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_big_endian_writer_1byte(writer, 0);
        __gquic_fill_str(writer, &msg->ser_name, 2);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
        
    }

    // ocsp_stapling
    if (msg->ocsp_stapling) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_big_endian_writer_1byte(writer, 1);
        gquic_big_endian_writer_2byte(writer, 0);
        gquic_big_endian_writer_2byte(writer, 0);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // supported_curves
    if (!gquic_list_head_empty(&msg->supported_curves)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SUPPORTED_CURVES);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        u_int16_t *curve;
        GQUIC_LIST_FOREACH(curve, &msg->supported_curves) gquic_big_endian_writer_2byte(writer, *curve);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // supported_points
    if (msg->supported_points.size > 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SUPPORTED_POINTS);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_fill_str(writer, &msg->supported_points, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // ticket_support
    if (msg->ticket_supported) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SESS_TICKET);
        __gquic_fill_str(writer, &msg->sess_ticket, 2);
    }

    // supported_sign_algos
    if (!gquic_list_head_empty(&msg->supported_sign_algos)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SIGN_ALGOS);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &msg->supported_sign_algos) gquic_big_endian_writer_2byte(writer, *sig);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // supported_sign_algos_cert
    if (!gquic_list_head_empty(&msg->supported_sign_algos_cert)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &msg->supported_sign_algos_cert) gquic_big_endian_writer_2byte(writer, *sig);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // secure_regegotation
    if (msg->secure_regegotiation_supported) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_fill_str(writer, &msg->secure_regegotation, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // alpn
    if (!gquic_list_head_empty(&msg->alpn_protos)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_ALPN);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->alpn_protos) __gquic_fill_str(writer, proto, 1);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // scts
    if (msg->scts) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SCT);
        gquic_big_endian_writer_2byte(writer, 0);
    }

    // supported_versions
    if (!gquic_list_head_empty(&msg->supported_versions)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 1);
        u_int16_t *vers;
        GQUIC_LIST_FOREACH(vers, &msg->supported_versions) gquic_big_endian_writer_2byte(writer, *vers);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // cookie
    if (msg->cookie.size > 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_COOKIE);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_fill_str(writer, &msg->cookie, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // key_shares
    if (!gquic_list_head_empty(&msg->key_shares)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_KEY_SHARE);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_tls_key_share_t *ks;
        GQUIC_LIST_FOREACH(ks, &msg->key_shares) {
            gquic_big_endian_writer_2byte(writer, ks->group);
            __gquic_fill_str(writer, &ks->data, 2);
        }
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // early_data
    if (msg->early_data) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_EARLY_DATA);
        gquic_big_endian_writer_2byte(writer, 0);
    }

    // psk_modes
    if (msg->psk_modes.size > 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_PSK_MODES);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_fill_str(writer, &msg->psk_modes, 1);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    // exts
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &msg->extensions) {
        gquic_big_endian_writer_2byte(writer, ext->type);
        __gquic_fill_str(writer, &ext->data, 2);
    }

    // psk_identities
    if (!gquic_list_head_empty(&msg->psk_identities)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_PRE_SHARED_KEY);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_tls_psk_identity_t *psk;
        GQUIC_LIST_FOREACH(psk, &msg->psk_identities) {
            __gquic_fill_str(writer, &psk->label, 2);
            gquic_big_endian_writer_4byte(writer, psk->obfuscated_ticket_age);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_str_t *binder;
        GQUIC_LIST_FOREACH(binder, &msg->psk_binders) {
            __gquic_fill_str(writer, binder, 1);
        }
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    return 0;
}

static int gquic_tls_client_hello_payload_deserialize(gquic_tls_client_hello_msg_t *msg, gquic_reader_str_t *const reader) {
    size_t prefix_len = 0;
    void *_ = NULL;
    void *field;
    if (msg == NULL || reader == NULL) {
        return -1;
    }

    // vers
    if (__gquic_recovery_bytes(&msg->vers, 2, reader) != 0) {
        return -2;
    }

    // random
    if (gquic_str_alloc(&msg->random, 32) != 0) {
        return -3;
    }
    if (gquic_reader_str_read(&msg->random, reader) != 0) {
        return -4;
    }

    // sess_id
    if (__gquic_recovery_str(&msg->sess_id, 1, reader) != 0) {
        return -2;
    }

    // cipher_suites
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
        return -2;
    }
    for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
        if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
            return -2;
        }
        *(u_int16_t *) field = 0;
        if (__gquic_recovery_bytes(field, 2, reader) != 0) {
            return -2;
        }
        if (gquic_list_insert_before(&msg->cipher_suites, field) != 0) {
            return -2;
        }
    }

    // compression_methods
    if (__gquic_recovery_str(&msg->compression_methods, 1, reader) != 0) {
        return -2;
    }

    // optional prefix len
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
        return -2;
    }
    if (prefix_len > GQUIC_STR_SIZE(reader)) {
        return -2;
    }
    gquic_reader_str_t opt_reader = { prefix_len, GQUIC_STR_VAL(reader) };
    if (gquic_tls_client_hello_optional_deserialize(msg, &opt_reader) < 0) {
        return -2;
    }
    gquic_reader_str_readed_size(reader, GQUIC_STR_VAL(&opt_reader) - GQUIC_STR_VAL(reader));

    return 0;
}

static int gquic_tls_client_hello_optional_deserialize(gquic_tls_client_hello_msg_t *msg, gquic_reader_str_t *const reader) {
    u_int16_t opt_type = 0;
    size_t prefix_len = 0;
    void *_ = NULL;
    void *field;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    while (GQUIC_STR_SIZE(reader) > 0) {
        opt_type = 0;
        if (__gquic_recovery_bytes(&opt_type, 2, reader) != 0) {
            return -2;
        }

        switch (opt_type) {

        case GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG:
            msg->next_proto_neg = 1;
            gquic_reader_str_readed_size(reader, 2);
            break;

        case GQUIC_TLS_EXTENSION_SERVER_NAME:
            gquic_reader_str_readed_size(reader, 2 + 2 + 1);
            if (__gquic_recovery_str(&msg->ser_name, 2, reader) != 0) {
                return -3;
            }
            break;

        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            msg->ocsp_stapling = 1;
            gquic_reader_str_readed_size(reader, 2 + 1 + 2 + 2);
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_CURVES:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -4;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    return -5;
                }
                *(u_int16_t *) field = 0;
                if (__gquic_recovery_bytes(field, 2, reader) != 0) {
                    return -6;
                }
                if (gquic_list_insert_before(&msg->supported_curves, field) != 0) {
                    return -7;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_POINTS:
            gquic_reader_str_readed_size(reader, 2);
            if (__gquic_recovery_str(&msg->supported_points, 1, reader) != 0) {
                return -8;
            }
            break;

        case GQUIC_TLS_EXTENSION_SESS_TICKET:
            msg->ticket_supported = 1;
            if (__gquic_recovery_str(&msg->sess_ticket, 2, reader) != 0) {
                return -9;
            }
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -10;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    return -11;
                }
                *(u_int16_t *) field = 0;
                if (__gquic_recovery_bytes(field, 2, reader) != 0) {
                    return -12;
                }
                if (gquic_list_insert_before(&msg->supported_sign_algos, field) != 0) {
                    return -13;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -14;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    return -15;
                }
                *(u_int16_t *) field = 0;
                if (__gquic_recovery_bytes(field, 2, reader) != 0) {
                    return -16;
                }
                if (gquic_list_insert_before(&msg->supported_sign_algos_cert, field) != 0) {
                    return -17;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO:
            gquic_reader_str_readed_size(reader, 2);
            msg->secure_regegotiation_supported = 1;
            if (__gquic_recovery_str(&msg->secure_regegotation, 1, reader) != 0) {
                return -18;
            }
            break;

        case GQUIC_TLS_EXTENSION_ALPN:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -19;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    return -20;
                }
                ((gquic_str_t *) field)->size = 0;
                if (__gquic_recovery_str(field, 1, reader) != 0) {
                    return -21;
                }
                if (gquic_list_insert_before(&msg->alpn_protos, field) != 0) {
                    return -22;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            gquic_reader_str_readed_size(reader, 2);
            msg->scts = 1;
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 1, reader) != 0) {
                return -23;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    return -24;
                }
                *(u_int16_t *) field = 0;
                if (__gquic_recovery_bytes(field, 2, reader) != 0) {
                    return -25;
                }
                if (gquic_list_insert_before(&msg->supported_versions, field) != 0) {
                    return -26;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_COOKIE:
            gquic_reader_str_readed_size(reader, 2);
            if (__gquic_recovery_str(&msg->cookie, 2, reader) != 0) {
                return -27;
            }
            break;

        case GQUIC_TLS_EXTENSION_KEY_SHARE:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -28;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_tls_key_share_t))) == NULL) {
                    return -29;
                }
                ((gquic_tls_key_share_t *) field)->group = 0;
                if (__gquic_recovery_bytes(&((gquic_tls_key_share_t *) field)->group, 2, reader) != 0) {
                    return -30;
                }
                if (__gquic_recovery_str(&((gquic_tls_key_share_t *) field)->data, 2, reader) != 0) {
                    return -31;
                }
                if (gquic_list_insert_before(&msg->key_shares, field) != 0) {
                    return -32;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_EARLY_DATA:
            gquic_reader_str_readed_size(reader, 2);
            msg->early_data = 1;
            break;

        case GQUIC_TLS_EXTENSION_PSK_MODES:
            gquic_reader_str_readed_size(reader, 2);
            if (__gquic_recovery_str(&msg->psk_modes, 1, reader) != 0) {
                return -33;
            }
            break;

        case GQUIC_TLS_EXTENSION_PRE_SHARED_KEY:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -34;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_tls_psk_identity_t))) == NULL) {
                    return -35;
                }
                if (__gquic_recovery_str(&((gquic_tls_psk_identity_t *) field)->label, 2, reader) != 0) {
                    return -36;
                }
                if (__gquic_recovery_bytes(&((gquic_tls_psk_identity_t *) field)->obfuscated_ticket_age, 4, reader) != 0) {
                    return -37;
                }
                if (gquic_list_insert_before(&msg->psk_identities, field) != 0) {
                    return -38;
                }
            }
            prefix_len = 0;
            if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
                return -39;
            }
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    return -40;
                }
                if (__gquic_recovery_str(field, 1, reader) != 0) {
                    return -41;
                }
                if (gquic_list_insert_before(&msg->psk_binders, field) != 0) {
                    return -42;
                }
            }
            break;

        default:
            if ((field = gquic_list_alloc(sizeof(gquic_tls_extension_t))) == NULL) {
                return -43;
            }
            ((gquic_tls_extension_t *) field)->type = opt_type;
            if (__gquic_recovery_str(&((gquic_tls_extension_t *) field)->data, 2, reader) != 0) {
                return -44;
            }
            if (gquic_list_insert_before(&msg->extensions, field) != 0) {
                return -45;
            }
        }
    }

    return 0;
}

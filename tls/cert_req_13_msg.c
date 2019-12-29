#include "tls/cert_req_13_msg.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/_msg_serialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/str.h"

static int gquic_tls_cert_req_13_msg_init(void *const msg);
static int gquic_tls_cert_req_13_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_req_13_msg_size(const void *const msg);
static ssize_t gquic_tls_cert_req_13_msg_serialize(const void *const msg, void *const buf, const size_t size);
static ssize_t gquic_tls_cert_req_13_msg_deserialize(void *const msg, const void *const buf, const size_t size);

gquic_tls_cert_req_13_msg_t *gquic_tls_cert_req_13_msg_alloc() {
    gquic_tls_cert_req_13_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_cert_req_13_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_cert_req_13_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_cert_req_13_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_cert_req_13_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_cert_req_13_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_cert_req_13_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ;

    return msg;
}

static int gquic_tls_cert_req_13_msg_init(void *const msg) {
    gquic_tls_cert_req_13_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    spec->ocsp_stapling = 0;
    spec->scts = 0;
    gquic_list_head_init(&spec->supported_sign_algo);
    gquic_list_head_init(&spec->supported_sign_algo_cert);
    gquic_list_head_init(&spec->cert_auths);
    return 0;
}

static int gquic_tls_cert_req_13_msg_dtor(void *const msg) {
    gquic_tls_cert_req_13_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    while (!gquic_list_head_empty(&spec->supported_sign_algo)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_sign_algo));
    }
    while (!gquic_list_head_empty(&spec->supported_sign_algo_cert)) {
        gquic_list_release(GQUIC_LIST_FIRST(&spec->supported_sign_algo_cert));
    }
    while (!gquic_list_head_empty(&spec->cert_auths)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&spec->cert_auths));
        gquic_list_release(GQUIC_LIST_FIRST(&spec->cert_auths));
    }
    gquic_tls_cert_req_13_msg_init(spec);
    return 0;
}

static ssize_t gquic_tls_cert_req_13_msg_size(const void *const msg) {
    const gquic_tls_cert_req_13_msg_t *const spec = msg;
    size_t off = 0;
    void *_;
    if (msg == NULL) {
        return -1;
    }
    off += 1 + 3 + 1 + 2;

    // ocsp_stapling
    if (spec->ocsp_stapling) {
        off += 4;
    }
    // scts
    if (spec->scts) {
        off += 4;
    }
    // supported_sign_algo
    if (!gquic_list_head_empty(&spec->supported_sign_algo)) {
        off += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &spec->supported_sign_algo) off += 2;
    }
    // supported_sign_algo_cert
    if (!gquic_list_head_empty(&spec->supported_sign_algo_cert)) {
        off += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &spec->supported_sign_algo_cert) off += 2;
    }
    // cert_auths
    if (!gquic_list_head_empty(&spec->cert_auths)) {
        off += 2 + 2 + 2;
        GQUIC_LIST_FOREACH(_, &spec->cert_auths) off += 2 + ((gquic_str_t *) _)->size;
    }

    return off;
}
static ssize_t gquic_tls_cert_req_13_msg_serialize(const void *const msg, void *const buf, const size_t size) {
    const gquic_tls_cert_req_13_msg_t *const spec = msg;
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_cert_req_13_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_1byte(buf, &off, 0);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);

    if (spec->ocsp_stapling) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
        __gquic_fill_2byte(buf, &off, 0);
    }

    if (spec->scts) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SCT);
        __gquic_fill_2byte(buf, &off, 0);
    }

    if (!gquic_list_head_empty(&spec->supported_sign_algo)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SIGN_ALGOS);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &spec->supported_sign_algo) __gquic_fill_2byte(buf, &off, *sig);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    if (!gquic_list_head_empty(&spec->supported_sign_algo_cert)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &spec->supported_sign_algo_cert) __gquic_fill_2byte(buf, &off, *sig);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    if (!gquic_list_head_empty(&spec->cert_auths)) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_CERT_AUTHS);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        gquic_str_t *ca;
        GQUIC_LIST_FOREACH(ca, &spec->cert_auths) {
            __gquic_fill_str_full(buf, &off, ca, 2);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }

    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

static ssize_t gquic_tls_cert_req_13_msg_deserialize(void *const msg, const void *const buf, const size_t size) {
    gquic_tls_cert_req_13_msg_t *const spec = msg;
    size_t off = 0;
    size_t prefix_len = 0;
    size_t _ = 0;
    size_t start_position = 0;
    size_t len = 0;
    u_int16_t opt_type = 0;
    void *field = NULL;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ) {
        return -2;
    }
    off += 3 + 1;
    if (__gquic_recovery_bytes(&len, 2, buf, size, &off) != 0) {
        return -3;
    }
    if (len > size - off) {
        return -3;
    }
    start_position = off;
    while (off - start_position < len) {
        opt_type = 0;
        if (__gquic_recovery_bytes(&opt_type, 2, buf, size, &off) != 0) {
            return -2;
        }
        
        switch (opt_type) {

        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            off += 2;
            spec->ocsp_stapling = 1;
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            off += 2;
            spec->scts = 1;
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
                if (gquic_list_insert_before(&spec->supported_sign_algo, field) != 0) {
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
                if (gquic_list_insert_before(&spec->supported_sign_algo_cert, field) != 0) {
                    return -2;
                }
            }
            break;

        case GQUIC_TLS_EXTENSION_CERT_AUTHS:
           off += 2;
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
                if (gquic_list_insert_before(&spec->cert_auths, field) != 0) {
                    return -2;
                }
            }
            break;

            
        }
    }

    return off;
}

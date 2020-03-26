#include "tls/cert_req_msg.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/_msg_serialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/str.h"
#include "exception.h"

static int gquic_tls_cert_req_msg_init(void *const msg);
static int gquic_tls_cert_req_msg_dtor(void *const msg);
static ssize_t gquic_tls_cert_req_msg_size(const void *const msg);
static int gquic_tls_cert_req_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_cert_req_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_cert_req_msg_t *gquic_tls_cert_req_msg_alloc() {
    gquic_tls_cert_req_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_cert_req_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_cert_req_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_cert_req_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_cert_req_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_cert_req_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_cert_req_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ;

    return msg;
}

static int gquic_tls_cert_req_msg_init(void *const msg) {
    gquic_tls_cert_req_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->ocsp_stapling = 0;
    spec->scts = 0;
    gquic_list_head_init(&spec->supported_sign_algo);
    gquic_list_head_init(&spec->supported_sign_algo_cert);
    gquic_list_head_init(&spec->cert_auths);

    return GQUIC_SUCCESS;
}

static int gquic_tls_cert_req_msg_dtor(void *const msg) {
    gquic_tls_cert_req_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
    gquic_tls_cert_req_msg_init(spec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_cert_req_msg_size(const void *const msg) {
    const gquic_tls_cert_req_msg_t *const spec = msg;
    size_t off = 0;
    void *_;
    if (msg == NULL) {
        return 0;
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
static int gquic_tls_cert_req_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_cert_req_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_cert_req_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    gquic_big_endian_writer_1byte(writer, 0);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 2);

    if (spec->ocsp_stapling) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_STATUS_REQUEST);
        gquic_big_endian_writer_2byte(writer, 0);
    }

    if (spec->scts) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SCT);
        gquic_big_endian_writer_2byte(writer, 0);
    }

    if (!gquic_list_head_empty(&spec->supported_sign_algo)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SIGN_ALGOS);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &spec->supported_sign_algo) gquic_big_endian_writer_2byte(writer, *sig);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    if (!gquic_list_head_empty(&spec->supported_sign_algo_cert)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        u_int16_t *sig;
        GQUIC_LIST_FOREACH(sig, &spec->supported_sign_algo_cert) gquic_big_endian_writer_2byte(writer, *sig);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    if (!gquic_list_head_empty(&spec->cert_auths)) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_CERT_AUTHS);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_str_t *ca;
        GQUIC_LIST_FOREACH(ca, &spec->cert_auths) {
            __gquic_fill_str(writer, ca, 2);
        }
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }

    __gquic_fill_prefix_len(&prefix_len_stack, writer);
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_cert_req_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_cert_req_msg_t *const spec = msg;
    size_t prefix_len = 0;
    void * _ = NULL;
    void * start_position = NULL;
    size_t len = 0;
    u_int16_t opt_type = 0;
    void *field = NULL;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    gquic_reader_str_readed_size(reader, 3 + 1);
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&len, 2, reader));
    if (len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    start_position = GQUIC_STR_VAL(reader);
    while ((size_t) (GQUIC_STR_VAL(reader) - start_position) < len) {
        opt_type = 0;
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&opt_type, 2, reader));
        
        switch (opt_type) {
        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            gquic_reader_str_readed_size(reader, 2);
            spec->ocsp_stapling = 1;
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            gquic_reader_str_readed_size(reader, 2);
            spec->scts = 1;
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
                }
                *(u_int16_t *) field = 0;
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(field, 2, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&spec->supported_sign_algo, field));
            }
            break;

        case GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
                }
                *(u_int16_t *) field = 0;
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(field, 2, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&spec->supported_sign_algo_cert, field));
            }
            break;

        case GQUIC_TLS_EXTENSION_CERT_AUTHS:
            gquic_reader_str_readed_size(reader, 2);
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                if ((field = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
                }
                gquic_str_init(field);
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(field, 2, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&spec->cert_auths, field));
            }
            break;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

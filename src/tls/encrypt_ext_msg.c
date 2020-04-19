#include "tls/encrypt_ext_msg.h"
#include "tls/common.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/_msg_serialize_util.h"
#include "tls/meta.h"

static int gquic_tls_encrypt_ext_msg_optional_deserialize(gquic_tls_encrypt_ext_msg_t *, gquic_reader_str_t *const);

static int gquic_tls_encrypt_ext_msg_init(void *const msg);
static int gquic_tls_encrypt_ext_msg_dtor(void *const msg);
static ssize_t gquic_tls_encrypt_ext_msg_size(const void *const msg);
static int gquic_tls_encrypt_ext_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_encrypt_ext_msg_deserialize(void *const msg, gquic_reader_str_t *const);


int gquic_tls_encrypt_ext_msg_alloc(gquic_tls_encrypt_ext_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_encrypt_ext_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_encrypt_ext_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_encrypt_ext_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_encrypt_ext_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_encrypt_ext_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_encrypt_ext_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_encrypt_ext_msg_init(void *const msg) {
    gquic_tls_encrypt_ext_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&spec->alpn_proto);
    gquic_list_head_init(&spec->addition_exts);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_encrypt_ext_msg_dtor(void *const msg) {
    gquic_tls_encrypt_ext_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->alpn_proto);
    while (!gquic_list_head_empty(&spec->addition_exts)) {
        gquic_str_reset(&((gquic_tls_extension_t *) GQUIC_LIST_FIRST(&spec->addition_exts))->data);
        gquic_list_release(GQUIC_LIST_FIRST(&spec->addition_exts));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_encrypt_ext_msg_size(const void *const msg) {
    const gquic_tls_encrypt_ext_msg_t *const spec = msg;
    size_t ret = 0;
    if (msg == NULL) {
        return 0;
    }
    // encrypted extensions
    ret += 1;
    // payload len
    ret += 3;
    // payload len (x2)
    ret += 2;
    // alpn
    if (GQUIC_STR_SIZE(&spec->alpn_proto) != 0) ret += 2 + 2 + 2 + 1 + GQUIC_STR_SIZE(&spec->alpn_proto);
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &spec->addition_exts) ret += 2 + 2 + ext->data.size;
    return ret;
}

static int gquic_tls_encrypt_ext_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_encrypt_ext_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    int _lazy = 0;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_encrypt_ext_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS);

    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
    if (GQUIC_STR_SIZE(&spec->alpn_proto) != 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_ALPN);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        __gquic_fill_str(writer, &spec->alpn_proto, 1);
        for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }
    gquic_tls_extension_t *ext;
    GQUIC_LIST_FOREACH(ext, &spec->addition_exts) {
        gquic_big_endian_writer_2byte(writer, ext->type);
        __gquic_fill_str(writer, &ext->data, 2);
    }
    for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_encrypt_ext_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    ssize_t prefix_len = 0;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    __gquic_recovery_bytes(&prefix_len, 3, reader);
    if ((size_t) prefix_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    __gquic_recovery_bytes(&prefix_len, 2, reader);
    if ((size_t) prefix_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_reader_str_t opt_reader = { prefix_len, GQUIC_STR_VAL(reader) };
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_encrypt_ext_msg_optional_deserialize(msg, &opt_reader));
    gquic_reader_str_readed_size(reader, GQUIC_STR_VAL(&opt_reader) - GQUIC_STR_VAL(reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_encrypt_ext_msg_optional_deserialize(gquic_tls_encrypt_ext_msg_t*msg, gquic_reader_str_t *const reader) {
    u_int16_t opt_type = 0;
    size_t prefix_len = 0;
    void *_ = NULL;
    gquic_tls_extension_t *field;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (GQUIC_STR_SIZE(reader) > 0) {
        opt_type = 0;
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&opt_type, 2, reader));

        switch (opt_type) {
        case GQUIC_TLS_EXTENSION_ALPN:
            gquic_reader_str_readed_size(reader, 2 + 2);
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 1, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) {
                u_int8_t *alpn = NULL;
                GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &alpn, sizeof(u_int8_t)));
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(alpn, 1, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(GQUIC_LIST_PAYLOAD(&msg->alpn_proto), alpn));
            }
            break;

        default:
            GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &field, sizeof(gquic_tls_extension_t)));
            field->type = opt_type;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&field->data, 2, reader));
            GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&msg->addition_exts, field));
            break;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

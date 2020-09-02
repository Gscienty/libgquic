/* src/tls/server_hello_msg.c TLS SERVER_HELLO record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/server_hello_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/meta.h"

static ssize_t gquic_tls_server_hello_msg_payload_size(const gquic_tls_server_hello_msg_t *);
static ssize_t gquic_tls_server_hello_msg_optional_size(const gquic_tls_server_hello_msg_t *);

static gquic_exception_t gquic_tls_server_hello_msg_payload_serialize(const gquic_tls_server_hello_msg_t *, gquic_writer_str_t *const);
static gquic_exception_t gquic_tls_server_hello_msg_optional_serialize(const gquic_tls_server_hello_msg_t *, gquic_writer_str_t *const);

static gquic_exception_t gquic_tls_server_hello_payload_deserialize(gquic_tls_server_hello_msg_t *, gquic_reader_str_t *const);
static gquic_exception_t gquic_tls_server_hello_optional_deserialize(gquic_tls_server_hello_msg_t *, gquic_reader_str_t *const);

static gquic_exception_t gquic_tls_server_hello_msg_init(void *const msg);
static gquic_exception_t gquic_tls_server_hello_msg_dtor(void *const msg);
static ssize_t gquic_tls_server_hello_msg_size(const void *const msg);
static gquic_exception_t gquic_tls_server_hello_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static gquic_exception_t gquic_tls_server_hello_msg_deserialize(void *const msg, gquic_reader_str_t *const);


gquic_exception_t gquic_tls_server_hello_msg_alloc(gquic_tls_server_hello_msg_t **const result) {
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_alloc((void **) result, sizeof(gquic_tls_server_hello_msg_t)));

    GQUIC_TLS_MSG_META(*result).deserialize_func = gquic_tls_server_hello_msg_deserialize;
    GQUIC_TLS_MSG_META(*result).dtor_func = gquic_tls_server_hello_msg_dtor;
    GQUIC_TLS_MSG_META(*result).init_func = gquic_tls_server_hello_msg_init;
    GQUIC_TLS_MSG_META(*result).serialize_func = gquic_tls_server_hello_msg_serialize;
    GQUIC_TLS_MSG_META(*result).size_func = gquic_tls_server_hello_msg_size;
    GQUIC_TLS_MSG_META(*result).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_msg_init(void *const msg) {
    gquic_tls_server_hello_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    spec->vers = 0;
    gquic_str_init(&spec->random);
    gquic_str_init(&spec->sess_id);
    spec->cipher_suite = 0;
    spec->compression_method = 0;
    spec->next_proto_neg = 0;
    gquic_list_head_init(&spec->next_protos);
    spec->ocsp_stapling = 0;
    spec->ticket_supported = 0;
    spec->secure_regegotiation_supported = 0;
    gquic_str_init(&spec->secure_regegotation);
    gquic_str_init(&spec->alpn_proto);
    gquic_list_head_init(&spec->scts);
    spec->supported_version = 0;
    gquic_str_init(&spec->ser_share.data);
    spec->ser_share.group = 0;
    spec->selected_identity_persent = 0;
    spec->selected_identity = 0;
    gquic_str_init(&spec->cookie);
    spec->selected_group = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_msg_dtor(void *const msg) {
    gquic_tls_server_hello_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->random);
    gquic_str_reset(&spec->sess_id);
    gquic_str_reset(&spec->secure_regegotation);
    gquic_str_reset(&spec->alpn_proto);
    gquic_str_reset(&spec->ser_share.data);
    gquic_str_reset(&spec->cookie);
    while (!gquic_list_head_empty(&spec->next_protos)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&spec->next_protos));
        gquic_list_release(GQUIC_LIST_FIRST(&spec->next_protos));
    }
    while (!gquic_list_head_empty(&spec->scts)) {
        gquic_str_reset(GQUIC_LIST_FIRST(&spec->scts));
        gquic_list_release(GQUIC_LIST_FIRST(&spec->scts));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_server_hello_msg_size(const void *const msg) {
    size_t ret = 0;
    if (msg == NULL) {
        return 0;
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
        return 0;
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
        return 0;
    }
    // next_proto_neg
    if (msg->next_proto_neg) {
        ret += 2 + 2;
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->next_protos) ret += 1 + proto->size;
    }
    // ocsp_stapling
    if (msg->ocsp_stapling) ret += 2 + 2;
    // ticket_supported
    if (msg->ticket_supported) ret += 2 + 2;
    // secure_regegotiation_supported
    if (msg->secure_regegotiation_supported) ret += 2 + 2 + 1 + msg->secure_regegotation.size;
    // alpn
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0) ret += 2 + 2 + 2 + 1 + GQUIC_STR_SIZE(&msg->alpn_proto);
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

static gquic_exception_t gquic_tls_server_hello_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_server_hello_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    // server_hello
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO);

    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_hello_msg_payload_serialize(msg, writer));
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_msg_payload_serialize(const gquic_tls_server_hello_msg_t *msg, gquic_writer_str_t *const writer) {
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_server_hello_msg_payload_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);

    // vers
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->vers));

    // random
    if (msg->random.size != 32) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &msg->random));

    // sess_id
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->sess_id, 1));

    // cipher_suite
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->cipher_suite));

    // compression_method
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, msg->compression_method));

    // optional prefix len
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_hello_msg_optional_serialize(msg, writer));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_msg_optional_serialize(const gquic_tls_server_hello_msg_t *msg, gquic_writer_str_t *const writer) {
    int _lazy = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_server_hello_msg_optional_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);

    // next_proto_neg
    if (msg->next_proto_neg) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        gquic_str_t *proto;
        GQUIC_LIST_FOREACH(proto, &msg->next_protos) {
            GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, proto, 1));
        }
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // ocsp_stapling
    if (msg->ocsp_stapling) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_STATUS_REQUEST));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, 0));
    }

    // ticket_supported
    if (msg->ticket_supported) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SESS_TICKET));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, 0));
    }

    // secure_regegotiation_supported
    if (msg->secure_regegotiation_supported) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->secure_regegotation, 1));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // alpn
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_ALPN));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->alpn_proto, 1));
        for (_lazy = 0; _lazy < 2; _lazy++) GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // scts
    if (!gquic_list_head_empty(&msg->scts)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SCT));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        gquic_str_t *sct;
        GQUIC_LIST_FOREACH(sct, &msg->scts) {
            GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, sct, 2));
        }
        for (_lazy = 0; _lazy < 2; _lazy++) GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // supported_version
    if (msg->supported_version) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->supported_version));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // ser_share
    if (msg->ser_share.group) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_KEY_SHARE));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->ser_share.group));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->ser_share.data, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // selected_identity_persent
    if (msg->selected_identity_persent) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_PRE_SHARED_KEY));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->selected_identity));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // cookie
    if (msg->cookie.size > 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_COOKIE));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &msg->cookie, 2));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    // selected_group
    if (msg->selected_group) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_KEY_SHARE));
        GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, msg->selected_group));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, writer));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    ssize_t ret = 0;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&ret, 3, reader));
    if ((size_t) ret > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_hello_payload_deserialize(msg, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_payload_deserialize(gquic_tls_server_hello_msg_t *msg, gquic_reader_str_t *const reader) {
    size_t prefix_len = 0;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    // vers
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->vers, 2, reader));

    // random
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&msg->random, 32));
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&msg->random, reader));

    // sess_id
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&msg->sess_id, 1, reader));

    // cipher_suite
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->cipher_suite, 2, reader));

    // compression_method
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->compression_method, 1, reader));

    // optional prefix len
    prefix_len = 0;
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
    if (prefix_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_reader_str_t opt_reader = { prefix_len, GQUIC_STR_VAL(reader) };
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_hello_optional_deserialize(msg, &opt_reader));
    gquic_reader_str_readed_size(reader, GQUIC_STR_VAL(&opt_reader) - GQUIC_STR_VAL(reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_server_hello_optional_deserialize(gquic_tls_server_hello_msg_t *msg, gquic_reader_str_t *const reader) {
    u_int16_t opt_type = 0;
    size_t prefix_len = 0;
    void *_ = NULL;
    void *field;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (GQUIC_STR_SIZE(reader) > 0) {
        opt_type = 0;
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&opt_type, 2, reader));

        switch (opt_type) {
        case GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG:
            msg->next_proto_neg = 1;
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) { 
                GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &field, sizeof(gquic_str_t)));
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(field, 1, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&msg->next_protos, field));
            }
            break;

        case GQUIC_TLS_EXTENSION_STATUS_REQUEST:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            msg->ocsp_stapling = 1;
            break;

        case GQUIC_TLS_EXTENSION_SESS_TICKET:
            msg->ticket_supported = 1;
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            break;

        case GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO:
            msg->secure_regegotiation_supported = 1;
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&msg->secure_regegotation, 1, reader));
            break;

        case GQUIC_TLS_EXTENSION_ALPN:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2 + 2));
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 1, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) { 
                u_int8_t *alpn = NULL;
                GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &alpn, sizeof(u_int8_t)));
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(alpn, 1, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(GQUIC_LIST_PAYLOAD(&msg->alpn_proto), alpn));
            }
            break;

        case GQUIC_TLS_EXTENSION_SCT:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            for (_ = GQUIC_STR_VAL(reader); (size_t) (GQUIC_STR_VAL(reader) - _) < prefix_len;) { 
                GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &field, sizeof(gquic_str_t)));
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(field, 2, reader));
                GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&msg->scts, field));
            }
            break;

        case GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->supported_version, 2, reader));
            break;

        case GQUIC_TLS_EXTENSION_KEY_SHARE:
            prefix_len = 0;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&prefix_len, 2, reader));
            if (prefix_len == 2) {
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->selected_group, 2, reader));
            }
            else {
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->ser_share.group, 2, reader));
                GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&msg->ser_share.data, 2, reader));
            }
            break;

        case GQUIC_TLS_EXTENSION_PRE_SHARED_KEY:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            msg->selected_identity_persent = 1;
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&msg->selected_identity, 2, reader));
            break;

        case GQUIC_TLS_EXTENSION_COOKIE:
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_readed_size(reader, 2));
            GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&msg->cookie, 2, reader));
            break;

        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

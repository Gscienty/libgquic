#include "tls/key_update_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_key_update_msg_init(void *const msg);
static int gquic_tls_key_update_msg_dtor(void *const msg);
static ssize_t gquic_tls_key_update_msg_size(const void *const msg);
static int gquic_tls_key_update_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_key_update_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_key_update_msg_t *gquic_tls_key_update_msg_alloc() {
    gquic_tls_key_update_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_key_update_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_key_update_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_key_update_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_key_update_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_key_update_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_key_update_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE;

    return msg;
}

static int gquic_tls_key_update_msg_init(void *const msg) {
    gquic_tls_key_update_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    spec->req = 0;
    return 0;
}

static int gquic_tls_key_update_msg_dtor(void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

static ssize_t gquic_tls_key_update_msg_size(const void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 1;
}

static int gquic_tls_key_update_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_key_update_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_key_update_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    if (spec->req) {
        gquic_big_endian_writer_1byte(writer, 1);
    }
    else {
        gquic_big_endian_writer_1byte(writer, 0);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, writer);

    return 0;
}

static int gquic_tls_key_update_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_key_update_msg_t *const spec = msg;
    size_t prefix_len = 0;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE) {
        return -2;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 3, reader) != 0) {
        return -3;
    }
    if (prefix_len > GQUIC_STR_SIZE(reader)) {
        return -4;
    }
    if (__gquic_recovery_bytes(&spec->req, 1, reader) != 0) {
        return -5;
    }
    return 0;
}


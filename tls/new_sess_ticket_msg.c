#include "tls/new_sess_ticket_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/list.h"
#include <unistd.h>

static int gquic_tls_new_sess_ticket_msg_init(void *const msg);
static int gquic_tls_new_sess_ticket_msg_dtor(void *const msg);
static ssize_t gquic_tls_new_sess_ticket_msg_size(const void *const msg);
static int gquic_tls_new_sess_ticket_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_new_sess_ticket_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_new_sess_ticket_msg_t *gquic_tls_new_sess_ticket_msg_alloc() {
    gquic_tls_new_sess_ticket_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_new_sess_ticket_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_new_sess_ticket_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_new_sess_ticket_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_new_sess_ticket_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_new_sess_ticket_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_new_sess_ticket_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET;

    return msg;
}

static int gquic_tls_new_sess_ticket_msg_init(void *const msg) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    spec->age_add = 0;
    spec->lifetime = 0;
    spec->max_early_data = 0;
    gquic_str_init(&spec->label);
    gquic_str_init(&spec->nonce);
    return 0;
}

static int gquic_tls_new_sess_ticket_msg_dtor(void *const msg) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&spec->label);
    gquic_str_reset(&spec->nonce);
    return 0;
}

static ssize_t gquic_tls_new_sess_ticket_msg_size(const void *const msg) {
    const gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 4 + 4 + 1 + spec->nonce.size + 2 + spec->label.size + 2 + (spec->max_early_data > 0 ? 2 + 2 + 4 : 0);
}

static int gquic_tls_new_sess_ticket_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    int _lazy = 0;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_new_sess_ticket_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 3);
    gquic_big_endian_writer_4byte(writer, spec->lifetime);
    gquic_big_endian_writer_4byte(writer, spec->age_add);
    __gquic_fill_str(writer, &spec->nonce, 1);
    __gquic_fill_str(writer, &spec->label, 2);
    __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
    if (spec->max_early_data > 0) {
        gquic_big_endian_writer_2byte(writer, GQUIC_TLS_EXTENSION_EARLY_DATA);
        __gquic_store_prefix_len(&prefix_len_stack, writer, 2);
        gquic_big_endian_writer_4byte(writer, spec->max_early_data);
        __gquic_fill_prefix_len(&prefix_len_stack, writer);
    }
    for (_lazy = 0; _lazy < 2; _lazy++) __gquic_fill_prefix_len(&prefix_len_stack, writer);

    return 0;
}

static int gquic_tls_new_sess_ticket_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_new_sess_ticket_msg_t *const spec = msg;
    size_t prefix_len;
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET) {
        return -2;
    }
    __gquic_recovery_bytes(&prefix_len, 3, reader);
    if ((size_t) prefix_len > GQUIC_STR_SIZE(reader)) {
        return -3;
    }
    if (__gquic_recovery_bytes(&spec->lifetime, 4, reader) != 0) {
        return -4;
    }
    if (__gquic_recovery_bytes(&spec->age_add, 4, reader) != 0) {
        return -5;
    }
    if (__gquic_recovery_str(&spec->nonce, 1, reader) != 0) {
        return -6;
    }
    if (__gquic_recovery_str(&spec->label, 2, reader) != 0) {
        return -7;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, reader) != 0) {
        return -8;
    }
    if (prefix_len > 0) {
        gquic_reader_str_readed_size(reader, 2 + 2);
        if (__gquic_recovery_bytes(&spec->max_early_data, 4, reader) != 0) {
            return -9;
        }
    }

    return 0;
}

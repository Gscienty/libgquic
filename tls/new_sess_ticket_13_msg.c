#include "tls/new_sess_ticket_13_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include "util/list.h"
#include <unistd.h>

static int gquic_tls_new_sess_ticket_13_msg_init(void *const msg);
static int gquic_tls_new_sess_ticket_13_msg_dtor(void *const msg);
static ssize_t gquic_tls_new_sess_ticket_13_msg_size(const void *const msg);
static ssize_t gquic_tls_new_sess_ticket_13_msg_serialize(const void *const msg, void *const buf, const size_t size);
static ssize_t gquic_tls_new_sess_ticket_13_msg_deserialize(void *const msg, const void *const buf, const size_t size);

gquic_tls_new_sess_ticket_13_msg_t *gquic_tls_new_sess_ticket_13_msg_alloc() {
    gquic_tls_new_sess_ticket_13_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_new_sess_ticket_13_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_new_sess_ticket_13_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_new_sess_ticket_13_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_new_sess_ticket_13_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_new_sess_ticket_13_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_new_sess_ticket_13_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET;

    return msg;
}

static int gquic_tls_new_sess_ticket_13_msg_init(void *const msg) {
    gquic_tls_new_sess_ticket_13_msg_t *const spec = msg;
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

static int gquic_tls_new_sess_ticket_13_msg_dtor(void *const msg) {
    gquic_tls_new_sess_ticket_13_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&spec->label);
    gquic_str_reset(&spec->nonce);
    return 0;
}

static ssize_t gquic_tls_new_sess_ticket_13_msg_size(const void *const msg) {
    const gquic_tls_new_sess_ticket_13_msg_t *const spec = msg;
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 4 + 4 + 1 + spec->nonce.size + 2 + spec->label.size + 2 + (spec->max_early_data > 0 ? 2 + 2 + 4 : 0);
}

static ssize_t gquic_tls_new_sess_ticket_13_msg_serialize(const void *const msg, void *const buf, const size_t size) {
    const gquic_tls_new_sess_ticket_13_msg_t *const spec = msg;
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_new_sess_ticket_13_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);

    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_4byte(buf, &off, spec->lifetime);
    __gquic_fill_4byte(buf, &off, spec->age_add);
    __gquic_fill_str_full(buf, &off, &spec->nonce, 1);
    __gquic_fill_str_full(buf, &off, &spec->label, 2);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if (spec->max_early_data > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_EARLY_DATA);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_4byte(buf, &off, spec->max_early_data);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

static ssize_t gquic_tls_new_sess_ticket_13_msg_deserialize(void *const msg, const void *const buf, const size_t size) {
    gquic_tls_new_sess_ticket_13_msg_t *const spec = msg;
    size_t off = 0;
    size_t prefix_len;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET) {
        return -2;
    }
    __gquic_recovery_bytes(&prefix_len, 3, buf, size, &off);
    if ((size_t) prefix_len > size - off) {
        return -3;
    }
    if (__gquic_recovery_bytes(&spec->lifetime, 4, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_bytes(&spec->age_add, 4, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str_full(&spec->nonce, 1, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str_full(&spec->label, 2, buf, size, &off) != 0) {
        return -2;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
        return -2;
    }
    if (prefix_len > 0) {
        off += 2 + 2;
        if (__gquic_recovery_bytes(&spec->max_early_data, 4, buf, size, &off) != 0) {
            return -2;
        }
    }

    return off;
}

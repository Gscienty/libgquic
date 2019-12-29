#include "tls/key_update_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_key_update_msg_init(void *const msg);
static int gquic_tls_key_update_msg_dtor(void *const msg);
static ssize_t gquic_tls_key_update_msg_size(const void *const msg);
static ssize_t gquic_tls_key_update_msg_serialize(const void *const msg, void *const buf, const size_t size);
static ssize_t gquic_tls_key_update_msg_deserialize(void *const msg, const void *const buf, const size_t size);

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

static ssize_t gquic_tls_key_update_msg_serialize(const void *const msg, void *const buf, const size_t size) {
    const gquic_tls_key_update_msg_t *const spec = msg;
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_key_update_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    if (spec->req) {
        __gquic_fill_1byte(buf, &off, 1);
    }
    else {
        __gquic_fill_1byte(buf, &off, 0);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

static ssize_t gquic_tls_key_update_msg_deserialize(void *const msg, const void *const buf, const size_t size) {
    gquic_tls_key_update_msg_t *const spec = msg;
    size_t off = 0;
    size_t prefix_len = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE) {
        return -2;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 3, buf, size, &off) != 0) {
        return -2;
    }
    if (prefix_len > size - off) {
        return -2;
    }
    if (__gquic_recovery_bytes(&spec->req, 1, buf, size, &off) != 0) {
        return -2;
    }
    return off;
}


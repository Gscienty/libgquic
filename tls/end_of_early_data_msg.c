#include "tls/end_of_early_data_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_end_of_early_data_msg_init(void *const msg);
static int gquic_tls_end_of_early_data_msg_dtor(void *const msg);
static ssize_t gquic_tls_end_of_early_data_msg_size(const void *const msg);
static ssize_t gquic_tls_end_of_early_data_msg_serialize(const void *const msg, void *const buf, const size_t size);
static ssize_t gquic_tls_end_of_early_data_msg_deserialize(void *const msg, const void *const buf, const size_t size);

gquic_tls_end_of_early_data_msg_t *gquic_tls_end_of_early_data_msg_alloc() {
    gquic_tls_end_of_early_data_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_end_of_early_data_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_end_of_early_data_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_end_of_early_data_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_end_of_early_data_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_end_of_early_data_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_end_of_early_data_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA;

    return msg;
}

static int gquic_tls_end_of_early_data_msg_init(void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

static int gquic_tls_end_of_early_data_msg_dtor(void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

static ssize_t gquic_tls_end_of_early_data_msg_size(const void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 4;
}

static ssize_t gquic_tls_end_of_early_data_msg_serialize(const void *const msg, void *const buf, const size_t size) {
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_end_of_early_data_msg_size(msg) > size) {
        return -2;
    }
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA);
    __gquic_fill_1byte(buf, &off, 0);
    __gquic_fill_2byte(buf, &off, 0);
    return off;
}

static ssize_t gquic_tls_end_of_early_data_msg_deserialize(void *const msg, const void *const buf, const size_t size) {
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[0] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA) {
        return -2;
    }
    if (4 > size) {
        return -2;
    }
    return 4;
}

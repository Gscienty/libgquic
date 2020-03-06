#include "tls/server_hello_done_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_server_hello_done_msg_init(void *const msg);
static int gquic_tls_server_hello_done_msg_dtor(void *const msg);
static ssize_t gquic_tls_server_hello_done_msg_size(const void *const msg);
static int gquic_tls_server_hello_done_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_server_hello_done_msg_deserialize(void *const msg, gquic_reader_str_t *const);

gquic_tls_server_hello_done_msg_t *gquic_tls_server_hello_done_msg_alloc() {
    gquic_tls_server_hello_done_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_server_hello_done_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_server_hello_done_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_server_hello_done_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_server_hello_done_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_server_hello_done_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_server_hello_done_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE;

    return msg;
}

static int gquic_tls_server_hello_done_msg_init(void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

static int gquic_tls_server_hello_done_msg_dtor(void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

static ssize_t gquic_tls_server_hello_done_msg_size(const void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    return 4;
}

static int gquic_tls_server_hello_done_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    size_t off = 0;
    if (msg == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_server_hello_done_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE);
    gquic_big_endian_writer_1byte(writer, 0);
    gquic_big_endian_writer_2byte(writer, 0);
    return off;
}

static int gquic_tls_server_hello_done_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    if (msg == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE) {
        return -2;
    }
    return gquic_reader_str_readed_size(reader, 3);
}

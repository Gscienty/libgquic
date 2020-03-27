#include "tls/server_key_exchange_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include "tls/meta.h"
#include <unistd.h>

static int gquic_tls_server_key_exchange_msg_init(void *const msg);
static int gquic_tls_server_key_exchange_msg_dtor(void *const msg);
static ssize_t gquic_tls_server_key_exchange_msg_size(const void *const msg);
static int gquic_tls_server_key_exchange_msg_serialize(const void *const msg, gquic_writer_str_t *const);
static int gquic_tls_server_key_exchange_msg_deserialize(void *const msg, gquic_reader_str_t *const);


gquic_tls_server_key_exchange_msg_t *gquic_tls_server_key_exchange_msg_alloc() {
    gquic_tls_server_key_exchange_msg_t *msg = gquic_tls_msg_alloc(sizeof(gquic_tls_server_key_exchange_msg_t));
    if (msg == NULL) {
        return NULL;
    }
    GQUIC_TLS_MSG_META(msg).deserialize_func = gquic_tls_server_key_exchange_msg_deserialize;
    GQUIC_TLS_MSG_META(msg).dtor_func = gquic_tls_server_key_exchange_msg_dtor;
    GQUIC_TLS_MSG_META(msg).init_func = gquic_tls_server_key_exchange_msg_init;
    GQUIC_TLS_MSG_META(msg).serialize_func = gquic_tls_server_key_exchange_msg_serialize;
    GQUIC_TLS_MSG_META(msg).size_func = gquic_tls_server_key_exchange_msg_size;
    GQUIC_TLS_MSG_META(msg).type = GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE;

    return msg;
}

static int gquic_tls_server_key_exchange_msg_init(void *const msg) {
    gquic_tls_server_key_exchange_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&spec->key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_server_key_exchange_msg_dtor(void *const msg) {
    gquic_tls_server_key_exchange_msg_t *const spec = msg;
    if (msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&spec->key);
    gquic_tls_server_key_exchange_msg_init(msg);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static ssize_t gquic_tls_server_key_exchange_msg_size(const void *const msg) {
    const gquic_tls_server_key_exchange_msg_t *const spec = msg;
    if (msg == NULL) {
        return 0;
    }
    return 1 + 3 + spec->key.size;
}

static int gquic_tls_server_key_exchange_msg_serialize(const void *const msg, gquic_writer_str_t *const writer) {
    const gquic_tls_server_key_exchange_msg_t *const spec = msg;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_server_key_exchange_msg_size(msg) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_list_head_init(&prefix_len_stack);
    gquic_big_endian_writer_1byte(writer, GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE);
    __gquic_fill_str(writer, &spec->key, 3);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_server_key_exchange_msg_deserialize(void *const msg, gquic_reader_str_t *const reader) {
    gquic_tls_server_key_exchange_msg_t *const spec = msg;
    if (msg == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_reader_str_read_byte(reader) != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&spec->key, 3, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

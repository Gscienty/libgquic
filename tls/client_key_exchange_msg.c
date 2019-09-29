#include "tls/client_key_exchange_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/config.h"
#include <unistd.h>

int gquic_tls_client_key_exchange_msg_init(gquic_tls_client_key_exchange_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_init(&msg->cipher);
    return 0;
}

int gquic_tls_client_key_exchange_msg_reset(gquic_tls_client_key_exchange_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->cipher);
    gquic_tls_client_key_exchange_msg_init(msg);
    return 0;
}

ssize_t gquic_tls_client_key_exchange_msg_size(const gquic_tls_client_key_exchange_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + msg->cipher.size;
}

ssize_t gquic_tls_client_key_exchange_msg_serialize(const gquic_tls_client_key_exchange_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_client_key_exchange_msg_size(msg) > size) {
        return -2;
    }
    gquic_list_head_init(&prefix_len_stack);
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 3);
    __gquic_fill_str(buf, &off, &msg->cipher);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);
    return off;
}

ssize_t gquic_tls_client_key_exchange_msg_deserialize(gquic_tls_client_key_exchange_msg_t *msg, const void *buf, const size_t size) {
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[off++] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE) {
        return -2;
    }
    if (__gquic_recovery_bytes(&msg->cipher.size, 3, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str(&msg->cipher, msg->cipher.size, buf, size, &off) != 0) {
        return -2;
    }
    return off;
}

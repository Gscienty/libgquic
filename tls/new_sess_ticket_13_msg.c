#include "tls/new_sess_ticket_13_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/config.h"
#include "util/list.h"
#include <unistd.h>

int gquic_tls_new_sess_ticket_13_msg_init(gquic_tls_new_sess_ticket_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    msg->age_add = 0;
    msg->lifetime = 0;
    msg->max_early_data = 0;
    gquic_str_init(&msg->label);
    gquic_str_init(&msg->nonce);
    return 0;
}

int gquic_tls_new_sess_ticket_13_msg_reset(gquic_tls_new_sess_ticket_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    gquic_str_reset(&msg->label);
    gquic_str_reset(&msg->nonce);
    return 0;
}

ssize_t gquic_tls_new_sess_ticket_13_msg_size(const gquic_tls_new_sess_ticket_13_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 1 + 3 + 4 + 4 + 1 + msg->nonce.size + 2 + msg->label.size + 2 + (msg->max_early_data > 0 ? 2 + 2 + 4 : 0);
}

ssize_t gquic_tls_new_sess_ticket_13_msg_serialize(const gquic_tls_new_sess_ticket_13_msg_t *msg, void *buf, const size_t size) {
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
    __gquic_fill_4byte(buf, &off, msg->lifetime);
    __gquic_fill_4byte(buf, &off, msg->age_add);
    __gquic_fill_str_full(buf, &off, &msg->nonce, 1);
    __gquic_fill_str_full(buf, &off, &msg->label, 2);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
    if (msg->max_early_data > 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TLS_EXTENSION_EARLY_DATA);
        __gquic_store_prefix_len(&prefix_len_stack, &off, 2);
        __gquic_fill_4byte(buf, &off, msg->max_early_data);
        __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    }
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 3);

    return off;
}

ssize_t gquic_tls_new_sess_ticket_13_msg_deserialize(gquic_tls_new_sess_ticket_13_msg_t *msg, const void *buf, const size_t size) {
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
    if (__gquic_recovery_bytes(&msg->lifetime, 4, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_bytes(&msg->age_add, 4, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str_full(&msg->nonce, 1, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_str_full(&msg->label, 2, buf, size, &off) != 0) {
        return -2;
    }
    prefix_len = 0;
    if (__gquic_recovery_bytes(&prefix_len, 2, buf, size, &off) != 0) {
        return -2;
    }
    if (prefix_len > 0) {
        off += 2 + 2;
        if (__gquic_recovery_bytes(&msg->max_early_data, 4, buf, size, &off) != 0) {
            return -2;
        }
    }

    return off;
}

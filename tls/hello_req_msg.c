#include "tls/hello_req_msg.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include <unistd.h>

int gquic_tls_hello_req_msg_init(gquic_tls_hello_req_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

int gquic_tls_hello_req_msg_reset(gquic_tls_hello_req_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 0;
}

ssize_t gquic_tls_hello_req_msg_size(const gquic_tls_hello_req_msg_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    return 4;
}

ssize_t gquic_tls_hello_req_msg_serialize(const gquic_tls_hello_req_msg_t *msg, void *buf, const size_t size) {
    size_t off = 0;
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_hello_req_msg_size(msg) > size) {
        return -2;
    }
    __gquic_fill_1byte(buf, &off, GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ);
    __gquic_fill_1byte(buf, &off, 0);
    __gquic_fill_2byte(buf, &off, 0);
    return off;
}

ssize_t gquic_tls_hello_req_msg_deserialize(gquic_tls_hello_req_msg_t *msg, const void *buf, const size_t size) {
    if (msg == NULL || buf == NULL) {
        return -1;
    }
    if (((unsigned char *) buf)[0] != GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ) {
        return -2;
    }
    if (4 > size) {
        return -2;
    }
    return 4;
}

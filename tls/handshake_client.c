#include "tls/handshake_client.h"

int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t *msg, const gquic_tls_conn_t *conn) {
    if (msg == NULL || conn == NULL) {
        return -1;
    }
    gquic_tls_client_hello_msg_init(msg);

    if (conn->cfg.ser_name.size == 0 && !conn->cfg.insecure_skiy_verify) {
        return -2;
    }
    gquic_str_t *proto;
    size_t next_protos_len = 0;
    GQUIC_LIST_FOREACH(proto, &conn->cfg.next_protos) {
        if (proto->size == 0 || proto->size > 255) {
            return -3;
        }
        next_protos_len += proto->size;
    }
    if (next_protos_len > 0xffff) {
        return -4;
    }
    return 0;
}

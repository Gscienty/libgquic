#include "net/conn.h"
#include <unistd.h>

int gquic_net_conn_init(gquic_net_conn_t *const conn) {
    if (conn == NULL) {
        return -1;
    }
    gquic_net_addr_init(&conn->addr);
    conn->fd = -1;
    conn->write.cb = NULL;
    conn->write.self = NULL;

    return 0;
}

int gquic_net_conn_write(gquic_net_conn_t *const conn, const gquic_str_t *const raw) {
    if (conn == NULL || raw == NULL) {
        return -1;
    }
    if (conn->write.self != NULL) {
        return GQUIC_NET_CONN_WRITE(conn, raw);
    }

    if (conn->addr.type == AF_INET) {
        return sendto(conn->fd, GQUIC_STR_VAL(raw), GQUIC_STR_SIZE(raw), 0, (struct sockaddr *) &conn->addr.addr.v4, sizeof(struct sockaddr_in));
    }
    else {
        return sendto(conn->fd, GQUIC_STR_VAL(raw), GQUIC_STR_SIZE(raw), 0, (struct sockaddr *) &conn->addr.addr.v6, sizeof(struct sockaddr_in6));
    }
}

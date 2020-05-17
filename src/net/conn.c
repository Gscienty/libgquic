#include "net/conn.h"
#include "exception.h"
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->write.self != NULL) {
        GQUIC_PROCESS_DONE(GQUIC_NET_CONN_WRITE(conn, raw));
    }
    if (conn->addr.type == AF_INET) {
        if (sendto(conn->fd, GQUIC_STR_VAL(raw), GQUIC_STR_SIZE(raw), 0, (struct sockaddr *) &conn->addr.addr.v4, sizeof(struct sockaddr_in)) < 0) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SENDTO_FAILED);
        }
    }
    else {
        if (sendto(conn->fd, GQUIC_STR_VAL(raw), GQUIC_STR_SIZE(raw), 0, (struct sockaddr *) &conn->addr.addr.v6, sizeof(struct sockaddr_in6))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SENDTO_FAILED);
        }
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

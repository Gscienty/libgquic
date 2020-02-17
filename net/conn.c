#include "net/conn.h"
#include <unistd.h>

int gquic_net_conn_write(gquic_net_conn_t *const conn, const gquic_str_t *const raw) {
    if (conn == NULL || raw == NULL) {
        return -1;
    }
    write(conn->fd, GQUIC_STR_VAL(raw), GQUIC_STR_SIZE(raw));
    return 0;
}

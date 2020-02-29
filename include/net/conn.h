#ifndef _LIBGQUIC_NET_CONN_H
#define _LIBGQUIC_NET_CONN_H

#include "net/addr.h"
#include "util/str.h"

typedef struct gquic_net_conn_s gquic_net_conn_t;
struct gquic_net_conn_s {
    gquic_net_addr_t addr;
    int fd;

    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } write;
};

#define GQUIC_NET_CONN_WRITE(writer, raw) ((writer)->write.cb((writer)->write.self, (raw)))

int gquic_net_conn_init(gquic_net_conn_t *const conn);
int gquic_net_conn_write(gquic_net_conn_t *const conn, const gquic_str_t *const raw);

#endif

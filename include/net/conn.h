#ifndef _LIBGQUIC_NET_CONN_H
#define _LIBGQUIC_NET_CONN_H

#include "util/str.h"

typedef struct gquic_net_conn_s gquic_net_conn_t;
struct gquic_net_conn_s {

};

int gquic_net_conn_write(gquic_net_conn_t *const conn, const gquic_str_t *const raw);

#endif

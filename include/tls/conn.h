#ifndef _LIBGQUIC_TLS_CONN_H
#define _LIBGQUIC_TLS_CONN_H

#include "tls/config.h"

typedef struct gquic_tls_conn_s gquic_tls_conn_t;
struct gquic_tls_conn_s {
    gquic_tls_config_t cfg;
};

#endif

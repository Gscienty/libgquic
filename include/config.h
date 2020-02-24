#ifndef _LIBGQUIC_CONFIG_H
#define _LIBGQUIC_CONFIG_H

#include <sys/types.h>
#include "util/list.h"
#include "util/str.h"
#include "tls/config.h"

typedef struct gquic_config_s gquic_config_t;
struct gquic_config_s {
    gquic_list_t versions;
    int conn_id_len;
    u_int64_t handshake_timeout;
    u_int64_t max_idle_timeout;
    u_int64_t max_recv_stream_flow_ctrl_wnd;
    u_int64_t max_recv_conn_flow_ctrl_wnd;
    u_int64_t max_incoming_uni_streams;
    u_int64_t max_incoming_streams;
    gquic_str_t stateless_reset_key;
    int keep_alive;

    gquic_tls_config_t tls_config;
};

#endif

#ifndef _LIBGQUIC_SESSION_H
#define _LIBGQUIC_SESSION_H

#include "net/conn.h"
#include "util/str.h"
#include "config.h"
#include "streams/stream_map.h"
#include "packet/send_queue.h"
#include "packet/conn_id_gen.h"

typedef struct gquic_session_s gquic_session_t;
struct gquic_session_s {
    gquic_str_t handshake_dst_conn_id;
    gquic_str_t origin_dst_conn_id;
    int src_conn_id_len;

    int is_client;
    u_int32_t version;
    gquic_config_t *cfg;

    gquic_net_conn_t *conn;
    gquic_packet_send_queue_t *send_queue;

    gquic_stream_map_t streams_map;
    gquic_conn_id_gen_t conn_id_gen;
};

#endif

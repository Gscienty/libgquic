#ifndef _LIBGQUIC_CLIENT_H
#define _LIBGQUIC_CLIENT_H

#include "packet/packet_handler_map.h"
#include "util/str.h"
#include "util/sem_list.h"
#include "net/conn.h"
#include "config.h"
#include "session.h"
#include "liteco.h"
#include <pthread.h>

typedef struct gquic_client_s gquic_client_t;
struct gquic_client_s {
    gquic_net_conn_t conn;
    gquic_packet_handler_map_t *packet_handlers;
    
    gquic_config_t *config;

    gquic_str_t src_conn_id;
    gquic_str_t dst_conn_id;

    u_int64_t initial_pn;

    int sess_created;
    gquic_session_t sess;
    pthread_t sess_run_thread;
    
    liteco_channel_t err_chain;
    liteco_channel_t handshake_complete_chain;
    liteco_channel_t done_chain;

    pthread_mutex_t mtx;
    _Atomic int connected;
};

int gquic_client_init(gquic_client_t *const client);
int gquic_client_create(gquic_client_t *const client,
                        const gquic_net_addr_t client_addr, const gquic_net_addr_t server_addr, gquic_config_t *const config);
int gquic_client_done(gquic_client_t *const client);
int gquic_client_close(gquic_client_t *const client);
int gquic_client_destory(gquic_client_t *const client, const int err);

int gquic_client_accept_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client, liteco_channel_t *const done_chan);
int gquic_client_accept_uni_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client, liteco_channel_t *const done_chan);
int gquic_client_open_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client);
int gquic_client_open_stream_sync(gquic_stream_t **const stream_storage, gquic_client_t *const client, liteco_channel_t *const done_chan);
int gquic_client_open_uni_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client);
int gquic_client_open_uni_stream_sync(gquic_stream_t **const stream_storage, gquic_client_t *const client, liteco_channel_t *const done_chan);

#endif

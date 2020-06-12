#ifndef _LIBGQUIC_SERVER_H
#define _LIBGQUIC_SERVER_H

#include "net/conn.h"
#include "packet/packet_handler_map.h"
#include "packet/received_packet.h"
#include "liteco.h"
#include "config.h"
#include "session.h"
#include <pthread.h>

typedef struct gquic_server_s gquic_server_t;
struct gquic_server_s {
    int accept_early_sess;
    int closed;
    int err;
    gquic_net_conn_t conn;
    gquic_config_t *config;

    gquic_packet_handler_map_t *packet_handlers;

    liteco_channel_t err_chain;
    liteco_channel_t sess_chain;
    liteco_channel_t done_chain;
    _Atomic int sess_count;

    pthread_mutex_t mtx;
};

int gquic_server_init(gquic_server_t *const server);
int gquic_server_ctor(gquic_server_t *const server, int fd, gquic_net_addr_t *const addr, gquic_config_t *const config, const int accept_early);
int gquic_server_accept(gquic_session_t **const session_storage, gquic_server_t *const server);
int gquic_server_close(gquic_server_t *const server);
int gquic_server_set_close_err(gquic_server_t *const server, const int err);
int gquic_server_handle_packet(gquic_server_t *const server, gquic_received_packet_t *const rp);

#endif

#ifndef _LIBGQUIC_CLIENT_H
#define _LIBGQUIC_CLIENT_H

#include "packet/packet_handler_map.h"
#include "util/str.h"
#include "util/sem_list.h"
#include "net/conn.h"
#include "config.h"
#include "session.h"
#include <semaphore.h>

typedef struct gquic_client_s gquic_client_t;
struct gquic_client_s {
    sem_t mtx;
    gquic_net_conn_t conn;
    int created_conn;
    gquic_packet_handler_map_t *packet_handlers;
    
    gquic_config_t *config;

    gquic_str_t src_conn_id;
    gquic_str_t dst_conn_id;

    u_int64_t initial_pn;

    int sess_created;
    gquic_session_t sess;
    pthread_t sess_run_thread;
    
    gquic_sem_list_t sec_conn_events;
};

int gquic_client_init(gquic_client_t *const client);
int gquic_client_create(gquic_client_t *const client, int fd, gquic_net_addr_t *const addr, gquic_config_t *const config, const int created);
int gquic_client_done(gquic_client_t *const client);
int gquic_client_close(gquic_client_t *const client);
int gquic_client_destory(gquic_client_t *const client, const int err);

#endif

#ifndef _LIBGQUIC_HANDSHAKE_ESTABLISH_H
#define _LIBGQUIC_HANDSHAKE_ESTABLISH_H

#include "tls/conn.h"
#include "tls/config.h"
#include "util/sem_list.h"
#include "util/str.h"
#include "util/io.h"
#include "handshake/auto_update_aead.h"
#include "handshake/aead.h"
#include <semaphore.h>

typedef struct gquic_handshake_event_s gquic_handshake_event_t;
struct gquic_handshake_event_s {
    void *self;
    int (*on_recv_params) (void *const, const gquic_str_t *const);
    int (*on_err) (void *const, const u_int16_t);
    int (*drop_keys) (void *const, const u_int16_t);
    int (*on_handshake_complete) (void *const);
};

int gquic_handshake_event_init(gquic_handshake_event_t *const event);

typedef struct gquic_handshake_establish_s gquic_handshake_establish_t;
struct gquic_handshake_establish_s {
    gquic_tls_config_t cfg;
    gquic_tls_conn_t conn;
    gquic_handshake_event_t events;
    gquic_sem_list_t msg_p;
    gquic_sem_list_t params_p;
    gquic_sem_list_t alert_p;
    sem_t handshake_done_sem;
    sem_t close_sem;
    int cli_hello_written;
    sem_t cli_hello_written_sem;
    sem_t recv_wkey_sem;
    sem_t recv_rkey_sem;
    sem_t write_record_sem;
    int is_client;
    sem_t mtx;
    u_int8_t read_enc_level;
    u_int8_t write_enc_level;
    gquic_io_t init_output;
    gquic_handshake_opener_t init_opener;
    gquic_handshake_sealer_t init_sealer;
    gquic_io_t handshake_output;
    gquic_handshake_opener_t handshake_opener;
    gquic_handshake_sealer_t handshake_sealer;
    gquic_io_t one_rtt_output;
    gquic_auto_update_aead_t aead;
    int has_1rtt_sealer;
    int has_1rtt_opener;
};

int gquic_handshake_establish_init(gquic_handshake_establish_t *const est);

#endif

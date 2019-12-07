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
    int (*on_err) (void *const, const u_int16_t, const int);
    int (*drop_keys) (void *const, const u_int16_t);
    int (*on_handshake_complete) (void *const);
};

#define GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(p, e) ((p)->on_recv_params((p)->self, (e)))
#define GQUIC_HANDSHAKE_EVENT_ON_ERR(p, a, e) ((p)->on_err((p)->self, (a), (e)))
#define GQUIC_HANDSHAKE_EVENT_DROP_KEYS(p, e) ((p)->drop_keys((p)->self, (e)))
#define GQUIC_HANDSHAKE_EVENT_ON_HANDSHAKE_COMPLETE(p) ((p)->on_handshake_complete((p)->self))

int gquic_handshake_event_init(gquic_handshake_event_t *const event);

typedef struct gquic_handshake_establish_s gquic_handshake_establish_t;
struct gquic_handshake_establish_s {
    gquic_tls_config_t cfg;
    gquic_tls_conn_t conn;
    gquic_handshake_event_t events;
    gquic_sem_list_t handshake_ending_events_queue;
    gquic_sem_list_t err_events_queue;
    gquic_sem_list_t msg_events_queue;
    gquic_sem_list_t handshake_process_events_queue;
    int cli_hello_written;
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
int gquic_handshake_establish_change_conn_id(gquic_handshake_establish_t *const est,
                                             const gquic_str_t *const conn_id);
int gquic_handshake_establish_1rtt_set_last_acked(gquic_handshake_establish_t *const est,
                                                  const u_int64_t pn);
int gquic_handshake_establish_run(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_close(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_handle_msg(gquic_handshake_establish_t *const est, const gquic_str_t *const data, u_int8_t env_level);
int gquic_handshake_establish_read_handshake_msg(gquic_str_t *const msg, gquic_handshake_establish_t *const est);

#endif

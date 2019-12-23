#ifndef _LIBGQUIC_HANDSHAKE_ESTABLISH_H
#define _LIBGQUIC_HANDSHAKE_ESTABLISH_H

#include "tls/conn.h"
#include "tls/config.h"
#include "util/sem_list.h"
#include "util/str.h"
#include "util/io.h"
#include "handshake/auto_update_aead.h"
#include "handshake/aead.h"
#include "handshake/transport_parameters.h"
#include "handshake/extension_handler.h"
#include <semaphore.h>

typedef struct gquic_establish_ending_event_s gquic_establish_ending_event_t;
struct gquic_establish_ending_event_s {
    u_int8_t type;
    union {
        void *event;
        u_int16_t alert_code;
    } payload;
};

#define GQUIC_ESTABLISH_ENDING_EVENT_HANDSHAKE_COMPLETE 1
#define GQUIC_ESTABLISH_ENDING_EVENT_ALERT 2
#define GQUIC_ESTABLISH_ENDING_EVENT_CLOSE 3
#define GQUIC_ESTABLISH_ENDING_EVENT_INTERNAL_ERR 4

typedef struct gquic_establish_err_event_s gquic_establish_err_event_t;
struct gquic_establish_err_event_s {
    int ret;
};

typedef struct gquic_establish_process_event_s gquic_establish_process_event_t;
struct gquic_establish_process_event_s {
    u_int8_t type;
    gquic_str_t param;
};

#define GQUIC_ESTABLISH_PROCESS_EVENT_DONE 1
#define GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD 2
#define GQUIC_ESTABLISH_PROCESS_EVENT_PARAM 3
#define GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY 4
#define GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY 5

typedef struct gquic_handshake_event_s gquic_handshake_event_t;
struct gquic_handshake_event_s {
    void *self;
    int (*on_recv_params) (void *const, const gquic_str_t *const);
    int (*on_err) (void *const, const u_int16_t, const int);
    int (*drop_keys) (void *const, const u_int16_t);
    int (*on_handshake_complete) (void *const);
};

#define GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(p, e) (((p) == NULL || (p)->on_recv_params == NULL || (p)->self == NULL) ? -1 : ((p)->on_recv_params((p)->self, (e))))
#define GQUIC_HANDSHAKE_EVENT_ON_ERR(p, a, e) (((p) == NULL || (p)->on_err == NULL || (p)->self == NULL) ? -1 : ((p)->on_err((p)->self, (a), (e))))
#define GQUIC_HANDSHAKE_EVENT_DROP_KEYS(p, e) (((p) == NULL || (p)->drop_keys == NULL || (p)->self == NULL) ? -1 : ((p)->drop_keys((p)->self, (e))))
#define GQUIC_HANDSHAKE_EVENT_ON_HANDSHAKE_COMPLETE(p) (((p) == NULL || (p)->on_handshake_complete == NULL || (p)->self == NULL) ? -1 : ((p)->on_handshake_complete((p)->self)))

int gquic_handshake_event_init(gquic_handshake_event_t *const event);

typedef struct gquic_handshake_establish_s gquic_handshake_establish_t;
struct gquic_handshake_establish_s {
    gquic_tls_config_t *cfg;
    gquic_tls_conn_t conn;
    gquic_handshake_event_t events;
    gquic_sem_list_t handshake_ending_events_queue;
    gquic_sem_list_t err_events_queue;
    gquic_sem_list_t msg_events_queue;
    gquic_sem_list_t handshake_process_events_queue;
    int cli_hello_written;
    int is_client;
    sem_t mtx;
    sem_t client_written_sem;
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

    gquic_handshake_extension_handler_t extension_handler;

    int handshake_done;
    sem_t handshake_done_notify;
};

int gquic_handshake_establish_init(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_release(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_assign(gquic_handshake_establish_t *const est,
                                     gquic_tls_config_t *const cfg,
                                     const gquic_str_t *const conn_id,
                                     const gquic_transport_parameters_t *const params,
                                     gquic_rtt_t *const rtt,
                                     const gquic_net_addr_t *const addr,
                                     const int is_client);
int gquic_handshake_establish_change_conn_id(gquic_handshake_establish_t *const est,
                                             const gquic_str_t *const conn_id);
int gquic_handshake_establish_1rtt_set_last_acked(gquic_handshake_establish_t *const est,
                                                  const u_int64_t pn);
int gquic_handshake_establish_run(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_close(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_handle_msg(gquic_handshake_establish_t *const est, const gquic_str_t *const data, const u_int8_t enc_level);
int gquic_handshake_establish_read_handshake_msg(gquic_str_t *const msg, gquic_handshake_establish_t *const est);
int gquic_handshake_establish_set_rkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec);
int gquic_handshake_establish_set_wkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec);
int gquic_handshake_establish_drop_initial_keys(gquic_handshake_establish_t *const est);
int gquic_handshake_establish_write_record(size_t *const size, gquic_handshake_establish_t *const est, const gquic_str_t *const data);
int gquic_handshake_establish_send_alert(gquic_handshake_establish_t *const est, const u_int8_t alert);
int gquic_handshake_establish_set_record_layer(gquic_tls_record_layer_t *const record_layer, gquic_handshake_establish_t *const est);

#endif

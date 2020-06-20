#ifndef _LIBGQUIC_SESSION_H
#define _LIBGQUIC_SESSION_H

#include "net/conn.h"
#include "util/str.h"
#include "util/rtt.h"
#include "util/sem_list.h"
#include "config.h"
#include "streams/stream_map.h"
#include "streams/crypto.h"
#include "streams/framer.h"
#include "packet/send_queue.h"
#include "packet/conn_id_gen.h"
#include "packet/conn_id_manager.h"
#include "packet/sent_packet_handler.h"
#include "packet/received_packet_handler.h"
#include "packet/retransmission_queue.h"
#include "packet/unpacker.h"
#include "packet/packer.h"
#include "packet/packet_handler_map.h"
#include "flowcontrol/wnd_update_queue.h"
#include "frame/parser.h"
#include "handshake/establish.h"
#include "handshake/transport_parameters.h"
#include "tls/config.h"
#include "liteco.h"

typedef struct gquic_session_s gquic_session_t;
struct gquic_session_s {
    gquic_str_t cli_dst_conn_id;
    gquic_str_t handshake_dst_conn_id;
    gquic_str_t origin_dst_conn_id;
    int src_conn_id_len;

    int is_client;
    u_int32_t version;
    gquic_config_t *cfg;

    gquic_net_conn_t *conn;
    gquic_packet_send_queue_t send_queue;

    gquic_stream_map_t streams_map;
    gquic_conn_id_gen_t conn_id_gen;
    gquic_conn_id_manager_t conn_id_manager;

    gquic_rtt_t rtt;

    gquic_crypto_stream_manager_t crypto_stream_manager;
    gquic_packet_sent_packet_handler_t sent_packet_handler;
    gquic_packet_received_packet_handlers_t recv_packet_handler;

    gquic_retransmission_queue_t retransmission;
    gquic_framer_t framer;
    gquic_wnd_update_queue_t wnd_update_queue;
    gquic_flowcontrol_conn_flow_ctrl_t conn_flow_ctrl;
    gquic_str_t token_store_key;
    // TODO token generator
    
    gquic_packet_packer_t packer;
    gquic_packet_unpacker_t unpacker;
    gquic_frame_parser_t frame_parser;

    gquic_handshake_establish_t est;

    liteco_channel_t close_chain;
    liteco_channel_t handshake_completed_chain;
    liteco_channel_t sending_schedule_chain;
    liteco_channel_t received_packet_chain;
    liteco_channel_t client_hello_writen_chain;

    int undecryptable_packets_count;
    gquic_list_t undecryptable_packets; /* received_packet * */

    int handshake_completed;

    int received_retry;
    int received_first_packet;

    u_int64_t idle_timeout;
    u_int64_t session_creation_time;
    u_int64_t last_packet_received_time;
    u_int64_t first_ack_eliciting_packet;
    u_int64_t pacing_deadline;
    
    int peer_params_seted;
    gquic_transport_parameters_t peer_params;
    
    u_int64_t deadline;

    int keep_alive_ping_sent;
    u_int64_t keep_alive_interval;

    gquic_packet_handler_map_t *runner;
    gquic_crypto_stream_t initial_stream;
    gquic_crypto_stream_t handshake_stream;
    gquic_post_handshake_crypto_stream_t one_rtt_stream;

    liteco_channel_t done_chain;
    pthread_mutex_t close_mtx;
    int close_flag;

    sem_t early_sess_ready;

    gquic_tls_config_t tls_config;

    struct {
        void *self;
        int (*cb) (void *const);
    } on_handshake_completed;
};

#define GQUIC_SESSION_ON_HANDSHAKE_COMPLETED(sess) \
    ((sess)->on_handshake_completed.cb == NULL \
    ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
    : ((sess)->on_handshake_completed.cb((sess)->on_handshake_completed.self)))

int gquic_session_init(gquic_session_t *const sess);
int gquic_session_ctor(gquic_session_t *const sess,
                       gquic_net_conn_t *const conn,
                       gquic_packet_handler_map_t *const runner,
                       const gquic_str_t *const origin_dst_conn_id,
                       const gquic_str_t *const cli_dst_conn_id,
                       const gquic_str_t *const dst_conn_id,
                       const gquic_str_t *const src_conn_id,
                       const gquic_str_t *const stateless_reset_token,
                       gquic_config_t *const cfg,
                       const u_int64_t initial_pn,
                       const int is_client);
int gquic_session_handle_packet(gquic_session_t *const sess, gquic_received_packet_t *const rp);
int gquic_session_close(gquic_session_t *const sess);
int gquic_session_destroy(gquic_session_t *const sess, const int err);
int gquic_session_queue_control_frame(gquic_session_t *const sess, void *const frame);
int gquic_session_run(gquic_session_t *const sess);

gquic_packet_handler_t *gquic_session_implement_packet_handler(gquic_session_t *const sess);

#endif

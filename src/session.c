#include "closed_session.h"
#include "session.h"
#include "frame/ping.h"
#include "frame/meta.h"
#include "frame/max_data.h"
#include "frame/path_challenge.h"
#include "frame/new_token.h"
#include "frame/retire_connection_id.h"
#include "frame/data_blocked.h"
#include "frame/handshake_done.h"
#include "util/stream_id.h"
#include "util/malloc.h"
#include "packet/send_mode.h"
#include "exception.h"
#include "coglobal.h"
#include "log.h"

static int gquic_session_config_transfer_tls_config(gquic_tls_config_t *const, gquic_config_t *const);
static int gquic_session_add_reset_token_wrapper(void *const, const gquic_str_t *const);
static int gquic_session_add_wrapper(gquic_str_t *const, void *const, const gquic_str_t *const);
static int gquic_session_handle_packet_wrapper(void *const, gquic_received_packet_t *const);
static int gquic_session_close_wrapper(void *const);
static int gquic_session_destroy_wrapper(void *const, const int);
static int gquic_session_queue_control_frame_wrapper(void *const, void *const);
static int gquic_session_on_handshake_complete_client_wrapper(void *const);
static int gquic_session_on_handshake_complete_server_wrapper(void *const);

static int gquic_session_on_has_conn_wnd_update_wrapper(void *const);
static int gquic_session_on_has_stream_wnd_update_wrapper(void *const, const u_int64_t);
static int gquic_session_on_has_stream_data_wrapper(void *const, const u_int64_t);
static int gquic_session_on_stream_completed_wrapper(void *const, const u_int64_t);
static int gquic_session_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const, void *const, const u_int64_t);
static int gquic_session_handshake_event_on_received_params_wrapper(void *const, const gquic_str_t *const);
static int gquic_session_handshake_event_on_error_wrapper(void *const, const u_int16_t, const int);
static int gquic_session_handshake_event_drop_keys_wrapper(void *const, const u_int8_t);

static int gquic_session_pre_setup(gquic_session_t *const);
static int gquic_session_process_transport_parameters(gquic_session_t *const, const gquic_str_t *const);
static int gquic_session_client_process_transport_parameters(gquic_transport_parameters_t *const, gquic_session_t *const, const gquic_str_t *const);
static int gquic_session_server_process_transport_parameters(gquic_transport_parameters_t *const, gquic_session_t *const, const gquic_str_t *const);
static int gquic_session_close_local(gquic_session_t *const, const int);
static int gquic_session_close_remote(gquic_session_t *const, const int);
static int gquic_session_drop_enc_lv(gquic_session_t *const, const u_int8_t);
static int gquic_session_schedule_sending(gquic_session_t *const);
static int gquic_session_destroy_inner(gquic_session_t *const, const int);
static int gquic_session_handle_handshake_completed(gquic_session_t *const);
static int gquic_session_try_reset_deadline(gquic_session_t *const);
static int gquic_session_handle_packet_inner(gquic_session_t *const, gquic_received_packet_t *const);
static int gquic_session_handle_single_packet(gquic_session_t *const, gquic_received_packet_t *const);
static int gquic_session_handle_retry_packet(gquic_session_t *const, const gquic_str_t *const);
static int gquic_session_try_queue_undecryptable_packet(gquic_session_t *const, gquic_received_packet_t *const);
static int gquic_session_try_decrypting_queued_packets(gquic_session_t *const);
static int gquic_session_handle_unpacked_packet(gquic_session_t *const, gquic_unpacked_packet_t *const, const u_int64_t);
static int gquic_session_handle_frame(gquic_session_t *const, void *const, const u_int8_t);
static int gquic_session_handle_stream_frame(gquic_session_t *const, gquic_frame_stream_t *const);
static int gquic_session_handle_crypto_frame(gquic_session_t *const, gquic_frame_crypto_t *const, const u_int8_t); 
static int gquic_session_handle_ack_frame(gquic_session_t *const, gquic_frame_ack_t *const, const u_int8_t);
static int gquic_session_handle_connection_close_frame(gquic_session_t *const, gquic_frame_connection_close_t *const);
static int gquic_session_handle_reset_stream_frame(gquic_session_t *const, gquic_frame_reset_stream_t *const);
static int gquic_session_handle_max_data_frame(gquic_session_t *const, gquic_frame_max_data_t *const);
static int gquic_session_handle_max_stream_data_frame(gquic_session_t *const, gquic_frame_max_stream_data_t *const);
static int gquic_session_handle_max_streams_frame(gquic_session_t *const, gquic_frame_max_streams_t *const);
static int gquic_session_handle_stop_sending_frame(gquic_session_t *const, gquic_frame_stop_sending_t *const);
static int gquic_session_handle_path_challenge_frame(gquic_session_t *const, gquic_frame_path_challenge_t *const);
static int gquic_session_handle_new_token_frame(gquic_session_t *const, gquic_frame_new_token_t *const);
static int gquic_session_handle_new_conn_id_frame(gquic_session_t *const, gquic_frame_new_connection_id_t *const);
static int gquic_session_handle_retire_conn_id_frame(gquic_session_t *const, gquic_frame_retire_connection_id_t *const);
static int gquic_session_handle_handshake_done_frame(gquic_session_t *const, gquic_frame_handshake_done_t *const);
static int gquic_session_send_packets(gquic_session_t *const);
static int gquic_session_send_connection_close(gquic_str_t *const,
                                               gquic_session_t *const,
                                               const int, const u_int64_t, const u_int64_t, const gquic_str_t *const);
static int gquic_session_try_send_only_ack_packet(gquic_session_t *const);
static int gquic_session_send_probe_packet(gquic_session_t *const, const u_int8_t);
static int gquic_session_send_packed_packet(gquic_session_t *const, gquic_packed_packet_t *const);
static int gquic_session_send_packet(int *const, gquic_session_t *const);
static int gquic_session_handle_close_err(gquic_session_t *const, const int, const int, const int);
static int gquic_session_handle_close_err_remote_alloc_closed_session(gquic_packet_handler_t **const, void *const);
static int gquic_session_handle_close_err_local_alloc_closed_session(gquic_packet_handler_t **const, void *const);

typedef struct __gquic_session_handle_close_err_local_params_s __gquic_session_handle_close_err_local_params_t;
struct __gquic_session_handle_close_err_local_params_s {
    gquic_session_t *sess;
    gquic_str_t close_packet;
};

static inline u_int64_t gquic_session_idle_timeout_start_time(gquic_session_t *const);

static int gquic_packet_handler_map_remove_reset_token_wrapper(void *const, const gquic_str_t *const);
static int gquic_packet_handler_map_retire_reset_token_wrapper(void *const, const gquic_str_t *const);
static int gquic_packet_handler_map_remove_wrapper(void *const, const gquic_str_t *const);
static int gquic_packet_handler_map_retire_wrapper(void *const, const gquic_str_t *const);
static int gquic_packet_handler_map_replace_with_closed_wrapper(void *const, const gquic_str_t *const, gquic_packet_handler_t *const);

static int gquic_session_implement_stream_sender(gquic_stream_sender_t *const, void *const);

static int gquic_initial_stream_write_wrapper(void *const, gquic_writer_str_t *const);
static int gquic_handshake_stream_write_wrapper(void *const, gquic_writer_str_t *const);
static int gquic_one_rtt_stream_write_wrapper(void *const, gquic_writer_str_t *const);

static int gquic_handshake_establish_handle_msg_wrapper(void *const, const gquic_str_t *const, const u_int8_t);
static int gquic_conn_id_manager_get_wrapper(gquic_str_t *const, void *const);
static int gquic_framer_queue_control_frame_wrapper(void *const, void *const);

static int gquic_session_client_written_callback(void *const);
static int gquic_session_run_handshake_co(void *const);
static int gquic_session_run_send_queue_co(void *const);


typedef struct gquic_session_close_event_s gquic_session_close_event_t;
struct gquic_session_close_event_s {
    int immediate;
    int err;
    int remote;
};

int gquic_session_init(gquic_session_t *const sess) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&sess->handshake_dst_conn_id);
    gquic_str_init(&sess->origin_dst_conn_id);
    sess->src_conn_id_len = 0;

    sess->is_client = 0;
    sess->version = 0;
    sess->cfg = NULL;

    sess->conn = NULL;
    gquic_packet_send_queue_init(&sess->send_queue);
    gquic_stream_map_init(&sess->streams_map);
    gquic_conn_id_gen_init(&sess->conn_id_gen);
    gquic_conn_id_manager_init(&sess->conn_id_manager);

    gquic_rtt_init(&sess->rtt);

    gquic_crypto_stream_manager_init(&sess->crypto_stream_manager);
    gquic_packet_sent_packet_handler_init(&sess->sent_packet_handler);
    gquic_packet_received_packet_handlers_init(&sess->recv_packet_handler);

    gquic_retransmission_queue_init(&sess->retransmission);
    gquic_framer_init(&sess->framer);
    gquic_wnd_update_queue_init(&sess->wnd_update_queue);
    gquic_flowcontrol_conn_flow_ctrl_init(&sess->conn_flow_ctrl);
    gquic_str_init(&sess->token_store_key);

    gquic_packet_packer_init(&sess->packer);
    gquic_packet_unpacker_init(&sess->unpacker);
    gquic_frame_parser_init(&sess->frame_parser);

    gquic_handshake_establish_init(&sess->est);

    liteco_channel_init(&sess->client_hello_writen_chain);
    liteco_channel_init(&sess->close_chain);
    liteco_channel_init(&sess->sending_schedule_chain);
    liteco_channel_init(&sess->received_packet_chain);
    liteco_channel_init(&sess->handshake_completed_chain);
    liteco_channel_init(&sess->ack_chan);

    sess->undecryptable_packets_count = 0;
    gquic_list_head_init(&sess->undecryptable_packets);

    sess->handshake_completed = 0;

    sess->received_retry = 0;
    sess->received_first_packet = 0;

    sess->idle_timeout = 0;
    sess->session_creation_time = 0;
    sess->last_packet_received_time = 0;
    sess->first_ack_eliciting_packet = 0;
    sess->pacing_deadline = 0;

    sess->peer_params_seted = 0;
    gquic_transport_parameters_init(&sess->peer_params);

    sess->deadline = 0;

    sess->keep_alive_ping_sent = 0;
    sess->keep_alive_interval = 0;

    sess->runner = NULL;
    gquic_crypto_stream_init(&sess->initial_stream);
    gquic_crypto_stream_init(&sess->handshake_stream);
    gquic_post_handshake_crypto_stream_init(&sess->one_rtt_stream);

    liteco_channel_init(&sess->done_chain);
    sess->close_flag = 0;
    pthread_mutex_init(&sess->close_mtx, NULL);

    sem_init(&sess->early_sess_ready, 0, 0);

    gquic_tls_config_init(&sess->tls_config);

    sess->on_handshake_completed.cb = NULL;
    sess->on_handshake_completed.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

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
                       const int is_client) {
    if (sess == NULL
        || conn == NULL
        || runner == NULL
        || dst_conn_id == NULL
        || src_conn_id == NULL
        || cfg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!is_client && cli_dst_conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_copy(&sess->cli_dst_conn_id, cli_dst_conn_id);
    sess->is_client = is_client;
    sess->conn = conn;
    sess->cfg = cfg;
    gquic_str_copy(&sess->handshake_dst_conn_id, dst_conn_id);
    sess->src_conn_id_len = GQUIC_STR_SIZE(src_conn_id);
    sess->is_client = is_client;
    sess->runner = runner;
    GQUIC_ASSERT_FAST_RETURN(gquic_session_config_transfer_tls_config(&sess->tls_config, sess->cfg));
    GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_manager_ctor(&sess->conn_id_manager,
                                                        &sess->handshake_dst_conn_id,
                                                        sess, gquic_session_add_reset_token_wrapper,
                                                        runner, gquic_packet_handler_map_remove_reset_token_wrapper,
                                                        runner, gquic_packet_handler_map_retire_reset_token_wrapper,
                                                        sess, gquic_session_queue_control_frame_wrapper));
    GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_gen_ctor(&sess->conn_id_gen,
                                                    src_conn_id,
                                                    &sess->cli_dst_conn_id,
                                                    sess, gquic_session_add_wrapper,
                                                    runner, gquic_packet_handler_map_remove_wrapper,
                                                    runner, gquic_packet_handler_map_retire_wrapper,
                                                    runner, gquic_packet_handler_map_replace_with_closed_wrapper,
                                                    sess, gquic_session_queue_control_frame_wrapper));
    GQUIC_ASSERT_FAST_RETURN(gquic_session_pre_setup(sess));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_ctor(&sess->sent_packet_handler, initial_pn, &sess->rtt));
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_ctor(&sess->initial_stream));
    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_ctor(&sess->handshake_stream));
    GQUIC_ASSERT_FAST_RETURN(gquic_post_handshake_crypto_ctor(&sess->one_rtt_stream, &sess->framer));

    gquic_transport_parameters_t params;
    gquic_transport_parameters_init(&params);
    params.init_max_stream_data_bidi_remote = 512 * (1 << 10);
    params.init_max_stream_data_bidi_local = 512 * (1 << 10);
    params.init_max_stream_data_uni = 512 * (1 << 10);
    params.init_max_data = 3 * 256 * (1 << 10);
    params.idle_timeout = cfg->max_idle_timeout;
    params.max_streams_bidi = cfg->max_incoming_streams;
    params.max_streams_uni = cfg->max_incoming_uni_streams;
    params.max_ack_delay = 25 * 1000 + 1000;
    params.ack_delay_exponent = 3;
    params.disable_migration = 1;
    params.active_conn_id_limit = 4;
    if (!is_client) {
        gquic_str_copy(&params.stateless_reset_token, stateless_reset_token);
        gquic_str_copy(&params.original_conn_id, origin_dst_conn_id);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_ctor(&sess->est,
                                                            &sess->initial_stream, gquic_initial_stream_write_wrapper,
                                                            &sess->handshake_stream, gquic_handshake_stream_write_wrapper,
                                                            &sess->one_rtt_stream, gquic_one_rtt_stream_write_wrapper,
                                                            is_client ? sess : NULL,
                                                            is_client ? gquic_session_client_written_callback : NULL,
                                                            &sess->tls_config,
                                                            is_client ? &sess->handshake_dst_conn_id : cli_dst_conn_id,
                                                            &params,
                                                            &sess->rtt,
                                                            &conn->addr,
                                                            sess->is_client));
    sess->est.events.on_recv_params.cb = gquic_session_handshake_event_on_received_params_wrapper;
    sess->est.events.on_recv_params.self = sess;
    sess->est.events.on_err.cb = gquic_session_handshake_event_on_error_wrapper;
    sess->est.events.on_err.self = sess;
    sess->est.events.drop_keys.cb = gquic_session_handshake_event_drop_keys_wrapper;
    sess->est.events.drop_keys.self = sess;
    sess->est.events.on_handshake_complete.cb = is_client
        ? gquic_session_on_handshake_complete_client_wrapper
        : gquic_session_on_handshake_complete_server_wrapper;
    sess->est.events.on_handshake_complete.self = sess;

    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_manager_ctor(&sess->crypto_stream_manager,
                                                              &sess->est, gquic_handshake_establish_handle_msg_wrapper,
                                                              &sess->initial_stream,
                                                              &sess->handshake_stream,
                                                              &sess->one_rtt_stream));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_unpacker_ctor(&sess->unpacker, &sess->est));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_packer_ctor(&sess->packer,
                                                      src_conn_id,
                                                      &sess->conn_id_manager, gquic_conn_id_manager_get_wrapper,
                                                      &sess->initial_stream,
                                                      &sess->handshake_stream,
                                                      &sess->sent_packet_handler,
                                                      &sess->retransmission,
                                                      conn->addr.type == AF_INET ? 1252 : 1232,
                                                      &sess->est,
                                                      &sess->framer,
                                                      &sess->recv_packet_handler,
                                                      sess->is_client));

    if (is_client && GQUIC_STR_SIZE(&sess->tls_config.ser_name) != 0) {
        gquic_str_copy(&sess->token_store_key, &sess->tls_config.ser_name);
    }
    // TODO is_client && token store
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_add_reset_token_wrapper(void *const sess_, const gquic_str_t *const token) {
    gquic_session_t *const sess = sess_;
    gquic_packet_handler_t *handler = NULL;
    if (sess == NULL || token == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((handler = gquic_session_implement_packet_handler(sess)) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_add_reset_token(sess->runner, token, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_add_wrapper(gquic_str_t *const token, void *const sess_, const gquic_str_t *const conn_id) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL || token == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_handler_map_add(token, sess->runner, conn_id, gquic_session_implement_packet_handler(sess));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_packet_handler_t *gquic_session_implement_packet_handler(gquic_session_t *const sess) {
    gquic_packet_handler_t *handler = NULL;
    if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&handler, gquic_packet_handler_t))) {
        return NULL;
    }
    handler->handle_packet.cb = gquic_session_handle_packet_wrapper;
    handler->handle_packet.self = sess;
    handler->closer.closer.cb = gquic_session_close_wrapper;
    handler->closer.closer.self = sess;
    handler->destroy.cb = gquic_session_destroy_wrapper;
    handler->destroy.self = sess;
    handler->is_client = sess->is_client;

    return handler;
}

static int gquic_session_handle_packet_wrapper(void *const sess, gquic_received_packet_t *const rp) {
    return gquic_session_handle_packet(sess, rp);
}

static int gquic_session_close_wrapper(void *const sess) {
    return gquic_session_close(sess);
}

static int gquic_session_destroy_wrapper(void *const sess, const int err) {
    return gquic_session_destroy(sess, err);
}

// maybe other thread
static int gquic_session_queue_control_frame_wrapper(void *const sess, void *const frame) {
    return gquic_session_queue_control_frame(sess, frame);
}

static int gquic_session_handshake_event_on_received_params_wrapper(void *const sess, const gquic_str_t *const data) {
    return gquic_session_process_transport_parameters(sess, data);
}

static int gquic_session_handshake_event_on_error_wrapper(void *const sess, const u_int16_t errcode, const int err) {
    (void) errcode;
    return gquic_session_close_local(sess, 10 * err - 1);
}

static int gquic_session_handshake_event_drop_keys_wrapper(void *const sess, const u_int8_t enc_lv) {
    return gquic_session_drop_enc_lv(sess, enc_lv);
}

static int gquic_packet_handler_map_remove_reset_token_wrapper(void *const handler, const gquic_str_t *const token) {
    return gquic_packet_handler_map_remove_reset_token(handler, token);
}

static int gquic_packet_handler_map_retire_reset_token_wrapper(void *const handler, const gquic_str_t *const token) {
    return gquic_packet_handler_map_retire_reset_token(handler, token);
}

static int gquic_packet_handler_map_remove_wrapper(void *const handler, const gquic_str_t *const conn_id) {
    return gquic_packet_handler_map_remove(handler, conn_id);
}

static int gquic_packet_handler_map_retire_wrapper(void *const handler, const gquic_str_t *const conn_id) {
    return gquic_packet_handler_map_retire(handler, conn_id);
}

static int gquic_packet_handler_map_replace_with_closed_wrapper(void *const handler, const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph) {
    return gquic_packet_handler_map_replace_with_closed(handler, conn_id, ph);
}

static int gquic_initial_stream_write_wrapper(void *const str, gquic_writer_str_t *const writer) {
    return gquic_crypto_stream_write(str, writer);
}

static int gquic_handshake_stream_write_wrapper(void *const str, gquic_writer_str_t *const writer) {
    return gquic_crypto_stream_write(str, writer);
}

static int gquic_one_rtt_stream_write_wrapper(void *const str, gquic_writer_str_t *const writer) {
    return gquic_post_handshake_crypto_write(str, writer);
}

static int gquic_handshake_establish_handle_msg_wrapper(void *const est, const gquic_str_t *const data, const u_int8_t enc_lv) {
    return gquic_handshake_establish_handle_msg(est, data, enc_lv);
}

static int gquic_conn_id_manager_get_wrapper(gquic_str_t *const ret, void *const manager) {
    return gquic_conn_id_manager_get_conn_id(ret, manager);
}

static int gquic_session_on_handshake_complete_client_wrapper(void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session(client) handshake completed");

    liteco_channel_close(&sess->handshake_completed_chain);
    GQUIC_SESSION_ON_HANDSHAKE_COMPLETED(sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_on_handshake_complete_server_wrapper(void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session(server) handshake completed");

    gquic_packet_handler_map_retire(sess->runner, &sess->cli_dst_conn_id);
    liteco_channel_close(&sess->handshake_completed_chain);
    GQUIC_SESSION_ON_HANDSHAKE_COMPLETED(sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_pre_setup(gquic_session_t *const sess) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_send_queue_ctor(&sess->send_queue, sess->conn);
    gquic_packet_received_packet_handlers_ctor(&sess->recv_packet_handler, &sess->rtt);
    gquic_flowcontrol_conn_flow_ctrl_ctor(&sess->conn_flow_ctrl,
                                          3 * 256 * (1 << 10),
                                          sess->cfg->max_recv_conn_flow_ctrl_wnd,
                                          sess, gquic_session_on_has_conn_wnd_update_wrapper,
                                          &sess->rtt);
    gquic_stream_map_ctor(&sess->streams_map,
                          sess, gquic_session_implement_stream_sender,
                          sess, gquic_session_stream_flow_ctrl_ctor,
                          sess->cfg->max_incoming_streams,
                          sess->cfg->max_incoming_uni_streams,
                          sess->is_client);
    gquic_framer_ctor(&sess->framer, &sess->streams_map);
    u_int64_t now = gquic_time_now();
    sess->last_packet_received_time = now;
    sess->session_creation_time = now;
    gquic_wnd_update_queue_ctor(&sess->wnd_update_queue,
                                &sess->streams_map,
                                &sess->conn_flow_ctrl,
                                &sess->framer, gquic_framer_queue_control_frame_wrapper);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_implement_stream_sender(gquic_stream_sender_t *const sender, void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL || sender == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sender->on_has_stream_data.self = sess;
    sender->on_has_stream_data.cb = gquic_session_on_has_stream_data_wrapper;
    sender->on_stream_completed.self = sess;
    sender->on_stream_completed.cb = gquic_session_on_stream_completed_wrapper;
    sender->queue_ctrl_frame.self = sess;
    sender->queue_ctrl_frame.cb = gquic_session_queue_control_frame_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_framer_queue_control_frame_wrapper(void *const framer, void *const frame) {
    return gquic_framer_queue_ctrl_frame(framer, frame);
}

static int gquic_session_on_has_conn_wnd_update_wrapper(void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_wnd_update_queue_add_conn(&sess->wnd_update_queue);
    gquic_session_schedule_sending(sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

// maybe other thread
static int gquic_session_on_has_stream_data_wrapper(void *const sess_, const u_int64_t stream_id) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_framer_add_active_stream(&sess->framer, stream_id);
    gquic_session_schedule_sending(sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

// maybe other thread
static int gquic_session_on_stream_completed_wrapper(void *const sess_, const u_int64_t stream_id) {
    int exception = GQUIC_SUCCESS;
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_stream_map_release_stream(&sess->streams_map, stream_id))) {
        gquic_session_close_local(sess, exception);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_schedule_sending(gquic_session_t *const sess) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_send(&sess->sending_schedule_chain, &sess->sending_schedule_chain);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_session_handle_packet(gquic_session_t *const sess, gquic_received_packet_t *const rp) {
    if (sess == NULL || rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_send(&sess->received_packet_chain, rp);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_session_close(gquic_session_t *const sess) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_session_close_local(sess, 0);
    GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, NULL, 0, &sess->done_chain);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_session_destroy(gquic_session_t *const sess, const int err) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_session_destroy_inner(sess, err);
    GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, NULL, 0, &sess->done_chain);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_destroy_inner(gquic_session_t *const sess, const int err) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sess->close_mtx);
    if (sess->close_flag) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    sess->close_flag = 1;
    gquic_session_close_event_t *event = NULL;
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&event, gquic_session_close_event_t))) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    event->err = err;
    event->immediate = 1;
    event->remote = 0;
    pthread_mutex_unlock(&sess->close_mtx);

    liteco_channel_send(&sess->close_chain, event);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_close_local(gquic_session_t *const sess, const int err) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sess->close_mtx);
    if (sess->close_flag) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    sess->close_flag = 1;
    gquic_session_close_event_t *event = NULL;
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&event, gquic_session_close_event_t))) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    event->err = err;
    event->immediate = 0;
    event->remote = 0;
    pthread_mutex_unlock(&sess->close_mtx);

    liteco_channel_send(&sess->close_chain, event);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_session_queue_control_frame(gquic_session_t *const sess, void *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_framer_queue_ctrl_frame(&sess->framer, frame);
    gquic_session_schedule_sending(sess);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_session_run(gquic_session_t *const sess) {
    int exception = GQUIC_SUCCESS;
    struct {
        int immediate;
        int err;
        int remote;
    } err_msg = { 0, 0, 0 };
    // TODO exception -> err
    const void *event = NULL;
    const liteco_channel_t *recv_chan = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coglobal_execute(gquic_session_run_handshake_co, sess);
    gquic_coglobal_execute(gquic_session_run_send_queue_co, sess);

    if (sess->is_client) {
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, &event, &recv_chan, 0, &sess->client_hello_writen_chain, &sess->close_chain);
        if (recv_chan == &sess->client_hello_writen_chain) {
            gquic_session_schedule_sending(sess);
        }
        else if (recv_chan == &sess->close_chain) {
            liteco_channel_send(&sess->close_chain, &sess->close_chain);
        }
    }

    for ( ;; ) {
        event = NULL;
        if (sess->handshake_completed) {
            GQUIC_COGLOBAL_CHANNEL_RECV(exception, &event, &recv_chan, 0, &sess->close_chain, &__CLOSED_CHAN__);
        }
        else {
            GQUIC_COGLOBAL_CHANNEL_RECV(exception, &event, &recv_chan, 0,
                                        &sess->close_chain,
                                        &sess->handshake_completed_chain,
                                        &__CLOSED_CHAN__);
        }
        if (recv_chan == &sess->handshake_completed_chain) {
            gquic_session_handle_handshake_completed(sess);
        }
        else if (recv_chan == &sess->close_chain) {
            err_msg.err = ((gquic_session_close_event_t *) event)->err;
            err_msg.immediate = ((gquic_session_close_event_t *) event)->immediate;
            err_msg.remote = ((gquic_session_close_event_t *) event)->remote;
            gquic_free((void *) event);
            goto closed;
        }

        event = NULL;
        gquic_session_try_reset_deadline(sess);

        if (sess->handshake_completed) {
            GQUIC_COGLOBAL_CHANNEL_RECV(exception, &event, &recv_chan, sess->deadline,
                                        &sess->close_chain,
                                        &sess->sending_schedule_chain,
                                        &sess->received_packet_chain);
        }
        else {
            GQUIC_COGLOBAL_CHANNEL_RECV(exception, &event, &recv_chan, sess->deadline,
                                        &sess->close_chain,
                                        &sess->sending_schedule_chain,
                                        &sess->received_packet_chain,
                                        &sess->handshake_completed_chain);
        }
        if (exception != GQUIC_EXCEPTION_TIMEOUT) {
            if (recv_chan == &sess->handshake_completed_chain) {
                GQUIC_LOG(GQUIC_LOG_DEBUG, "session recv handshake completed signal");

                gquic_session_handle_handshake_completed(sess);
            }
            else if (recv_chan == &sess->received_packet_chain) {
                GQUIC_LOG(GQUIC_LOG_DEBUG, "session recv received packet signal");

                if (!gquic_session_handle_packet_inner(sess, (gquic_received_packet_t *) event)) {
                    gquic_free((void *) event);
                    continue;
                }
                gquic_free((void *) event);
            }
            else if (recv_chan == &sess->close_chain) {
                GQUIC_LOG(GQUIC_LOG_DEBUG, "session recv close signal");

                err_msg.err = ((gquic_session_close_event_t *) event)->err;
                err_msg.immediate = ((gquic_session_close_event_t *) event)->immediate;
                err_msg.remote = ((gquic_session_close_event_t *) event)->remote;
                gquic_free((void *) event);
                goto closed;
            }
#if LOG
            else {
                GQUIC_LOG(GQUIC_LOG_DEBUG, "session recv sending schedule signal");
            }
#endif
        }
#if LOG
        else {
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session timeout");
        }
#endif

        u_int64_t now = gquic_time_now();
        if (sess->sent_packet_handler.alarm != 0 && sess->sent_packet_handler.alarm < now) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_packet_handler_on_loss_detection_timeout(&sess->sent_packet_handler))) {
                gquic_session_close_local(sess, exception);
                exception = GQUIC_SUCCESS;
            }
        }

        u_int64_t pacing_deadline = 0;
        if (sess->pacing_deadline == 0) {
            pacing_deadline = sess->sent_packet_handler.next_send_time;
        }

        if (sess->cfg->keep_alive
            && !sess->keep_alive_ping_sent
            && sess->handshake_completed
            && sess->first_ack_eliciting_packet == 0
            && now - sess->last_packet_received_time >= sess->keep_alive_interval / 2) {
            gquic_frame_ping_t *ping = NULL;
            gquic_frame_ping_alloc(&ping);
            gquic_framer_queue_ctrl_frame(&sess->framer, ping);
            sess->keep_alive_ping_sent = 1;
        }
        else if (pacing_deadline != 0 && now < pacing_deadline) {
            sess->pacing_deadline = pacing_deadline;
            continue;
        }

        if (!sess->handshake_completed && now - sess->session_creation_time >= sess->cfg->handshake_timeout) {
            GQUIC_LOG(GQUIC_LOG_INFO, "session handshake timeout");

            gquic_session_destroy_inner(sess, GQUIC_EXCEPTION_HANDSHAKE_TIMEOUT);
            continue;
        }
        if (sess->handshake_completed && now - gquic_session_idle_timeout_start_time(sess) >= sess->idle_timeout) {
            GQUIC_LOG(GQUIC_LOG_INFO, "session idle timeout");

            gquic_session_destroy_inner(sess, GQUIC_EXCEPTION_IDLE_TIMEOUT);
            continue;
        }

        if (GQUIC_ASSERT_CAUSE(exception, gquic_session_send_packets(sess))) {
            GQUIC_LOG(GQUIC_LOG_ERROR, "session send packets error");

            gquic_session_close_local(sess, exception);
            exception = GQUIC_SUCCESS;
        }
    }
closed:
    GQUIC_LOG(GQUIC_LOG_DEBUG, "session finished");

    gquic_session_handle_close_err(sess, err_msg.err, err_msg.immediate, err_msg.remote);
    gquic_handshake_establish_close(&sess->est);
    gquic_packet_send_queue_close(&sess->send_queue);

    liteco_channel_close(&sess->done_chain);

    GQUIC_PROCESS_DONE(err_msg.err);
}

static int gquic_session_run_handshake_co(void *const sess_) {
    int exception = GQUIC_SUCCESS;
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_handshake_establish_run(&sess->est))) {
        gquic_session_close_local(sess, exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_run_send_queue_co(void *const sess_) {
    int exception = GQUIC_SUCCESS;
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_send_queue_run(&sess->send_queue))) {
        gquic_session_close_local(sess, exception);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_client_written_callback(void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_close(&sess->client_hello_writen_chain);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_try_reset_deadline(gquic_session_t *const sess) {
    u_int64_t tmp = 0;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!sess->handshake_completed) {
        sess->deadline = sess->session_creation_time + sess->cfg->handshake_timeout;

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    if (sess->cfg->keep_alive && !sess->keep_alive_ping_sent) {
        sess->deadline = gquic_session_idle_timeout_start_time(sess) + sess->keep_alive_interval / 2;
    }
    else {
        sess->deadline = gquic_session_idle_timeout_start_time(sess) + sess->idle_timeout;
    }

    if ((tmp = gquic_packet_received_packet_handlers_get_alarm_timeout(&sess->recv_packet_handler)) != 0) {
        sess->deadline = tmp < sess->deadline ? tmp : sess->deadline;
    }
    if ((tmp = sess->sent_packet_handler.alarm) != 0) {
        sess->deadline = tmp < sess->deadline ? tmp : sess->deadline;
    }
    if ((tmp = sess->pacing_deadline) != 0) {
        sess->deadline = tmp < sess->deadline ? tmp : sess->deadline;
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const stream_flow_ctrl,
                                               void *const sess_, const u_int64_t stream_id) {
    u_int64_t initial_swnd = 0;
    gquic_session_t *const sess = sess_;
    if (stream_flow_ctrl == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (sess->peer_params_seted) {
        if (!gquic_stream_id_is_bidi(stream_id)) {
            initial_swnd = sess->peer_params.init_max_stream_data_uni;
        }
        else {
            if (gquic_stream_id_is_client(stream_id) == sess->is_client) {
                initial_swnd = sess->peer_params.init_max_stream_data_bidi_remote;
            }
            else {
                initial_swnd = sess->peer_params.init_max_stream_data_bidi_local;
            }
        }
    }

    GQUIC_PROCESS_DONE(gquic_flowcontrol_stream_flow_ctrl_ctor(stream_flow_ctrl,
                                                               stream_id,
                                                               &sess->conn_flow_ctrl,
                                                               512 * (1 << 10),
                                                               sess->cfg->max_recv_stream_flow_ctrl_wnd,
                                                               initial_swnd,
                                                               sess,
                                                               gquic_session_on_has_stream_wnd_update_wrapper,
                                                               &sess->rtt));
}

static int gquic_session_on_has_stream_wnd_update_wrapper(void *const sess_, const u_int64_t stream_id) {
    gquic_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_wnd_update_queue_add_stream(&sess->wnd_update_queue, stream_id);
    gquic_session_schedule_sending(sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_process_transport_parameters(gquic_session_t *const sess, const gquic_str_t *const data) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (sess->is_client) {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_client_process_transport_parameters(&sess->peer_params, sess, data));
    }
    else {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_server_process_transport_parameters(&sess->peer_params, sess, data));
    }
    if (exception != GQUIC_SUCCESS) {
        gquic_session_close_local(sess, exception);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    sess->peer_params_seted = 1;
    sess->idle_timeout = sess->cfg->max_idle_timeout;
    if (sess->idle_timeout == 0) {
        sess->idle_timeout = sess->peer_params.idle_timeout;
    }
    else if (sess->peer_params.idle_timeout < sess->idle_timeout) {
        sess->idle_timeout = sess->peer_params.idle_timeout;
    }
    sess->keep_alive_interval = sess->idle_timeout / 2 < 20 * 1000 * 1000 ? sess->idle_timeout / 2 : 20 * 1000 * 1000;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_stream_map_handle_update_limits(&sess->streams_map, &sess->peer_params))) {
        gquic_session_close_local(sess, exception);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (sess->peer_params.max_packet_size != 0) {
        sess->packer.max_packet_size = sess->packer.max_packet_size < sess->peer_params.max_packet_size
            ? sess->packer.max_packet_size
            : sess->peer_params.max_packet_size;
    }
    sess->frame_parser.ack_delay_exponent = sess->peer_params.ack_delay_exponent;
    gquic_flowcontrol_base_update_swnd(&sess->conn_flow_ctrl.base, sess->peer_params.init_max_data);
    sess->rtt.max_delay = sess->peer_params.max_ack_delay;
    gquic_conn_id_gen_set_max_active_conn_ids(&sess->conn_id_gen, sess->peer_params.active_conn_id_limit);
    if (GQUIC_STR_SIZE(&sess->peer_params.stateless_reset_token) != 0) {
        gquic_conn_id_manager_set_stateless_reset_token(&sess->conn_id_manager, &sess->peer_params.stateless_reset_token);
    }

    sem_post(&sess->early_sess_ready);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_client_process_transport_parameters(gquic_transport_parameters_t *const params,
                                                             gquic_session_t *const sess,
                                                             const gquic_str_t *const data) {
    if (params == NULL || sess == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_reader_str_t reader = *data;
    GQUIC_ASSERT_FAST_RETURN(gquic_transport_parameters_deserialize(params, &reader));
    if (gquic_str_cmp(&params->original_conn_id, &sess->origin_dst_conn_id) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CONN_ID_NOT_EQUAL);
    }
    // TODO prefered_address
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_server_process_transport_parameters(gquic_transport_parameters_t *const params,
                                                             gquic_session_t *const sess,
                                                             const gquic_str_t *const data) {
    if (params == NULL || sess == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_reader_str_t reader = *data;
    GQUIC_ASSERT_FAST_RETURN(gquic_transport_parameters_deserialize(params, &reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_drop_enc_lv(gquic_session_t *const sess, const u_int8_t enc_lv) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_sent_packet_handler_drop_packets(&sess->sent_packet_handler, enc_lv);
    gquic_packet_received_packet_handlers_drop_packets(&sess->recv_packet_handler, enc_lv);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_handshake_completed(gquic_session_t *const sess) {
    gquic_frame_handshake_done_t *frame = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sess->handshake_completed = 1;

    gquic_conn_id_gen_set_handshake_complete(&sess->conn_id_gen);
    gquic_packet_sent_packet_handler_set_handshake_complete(&sess->sent_packet_handler);

    if (!sess->is_client) {
        // TODO gen token
        gquic_handshake_establish_drop_handshake_keys(&sess->est);

        GQUIC_LOG(GQUIC_LOG_INFO, "session send HANDSHAKE_DONE frame");
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_handshake_done_alloc(&frame));
        GQUIC_ASSERT_FAST_RETURN(gquic_session_queue_control_frame(sess, frame));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline u_int64_t gquic_session_idle_timeout_start_time(gquic_session_t *const sess) {
    return sess->last_packet_received_time > sess->first_ack_eliciting_packet
        ? sess->last_packet_received_time
        : sess->first_ack_eliciting_packet;
}

static int gquic_session_handle_packet_inner(gquic_session_t *const sess, gquic_received_packet_t *const rp) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    int counter = 0;
    int processed = 0;
    gquic_reader_str_t data = { 0, NULL };
    gquic_packet_buffer_t *buffer = NULL;
    gquic_received_packet_t *p = NULL;
    if (sess == NULL || rp == NULL) {
        return 0;
    }
    data = rp->data;
    p = rp;
    GQUIC_CPTR_ASSIGN(exception, &buffer, p->buffer, gquic_cptr_packet_buffer_t, buffer, cptr);

    while (GQUIC_STR_SIZE(&data) != 0) {
        if (counter > 0) {
            gquic_received_packet_t *prev_p = p;
            gquic_received_packet_copy(&p, p);
            p->data = data;

            if (prev_p != rp) {
                gquic_free(prev_p);
            }
        }
       if (GQUIC_ASSERT(gquic_packet_header_deserialize_packet_len(&p->data.size, &data, sess->src_conn_id_len))) {
           break;
       }
       if (gquic_packet_header_deserlialize_type(&p->data) == GQUIC_LONG_HEADER_RETRY) {
           p->data = data;
       }
       gquic_reader_str_readed_size(&data, GQUIC_STR_SIZE(&p->data));

       if (GQUIC_ASSERT(gquic_packet_header_deserialize_conn_id(&p->dst_conn_id, &p->data, sess->src_conn_id_len))) {
           break;
       }
       if (counter > 0) {
           gquic_count_pointer_ref(&GQUIC_CPTR_CONTAIN_OF(p->buffer, gquic_cptr_packet_buffer_t, buffer)->cptr);
       }
       counter++;
       processed = gquic_session_handle_single_packet(sess, p);
    }

    gquic_packet_buffer_put(buffer);

    if (p != rp) {
        gquic_free(p);
    }

    return processed;
}

static int gquic_session_handle_single_packet(gquic_session_t *const sess, gquic_received_packet_t *const rp) {
    int ret = 0;
    int exception = GQUIC_SUCCESS;
    int was_queued = 0;
    gquic_packet_buffer_t *buffer = NULL;
    gquic_unpacked_packet_t packet;
    if (sess == NULL || rp == NULL) {
        return 0;
    }
    gquic_unpacked_packet_init(&packet);
    buffer = rp->buffer;

    if (gquic_packet_header_deserlialize_type(&rp->data) == GQUIC_LONG_HEADER_RETRY) {
        ret = gquic_session_handle_retry_packet(sess, &rp->data);
        goto finished;
    }

    gquic_str_t src_conn_id = { 0, NULL };
    if ((GQUIC_STR_FIRST_BYTE(&rp->data) & 0x80) != 0) {
        gquic_packet_header_deserialize_src_conn_id(&src_conn_id, &rp->data);
    }
    if (sess->received_first_packet
        && (GQUIC_STR_FIRST_BYTE(&rp->data) & 0x80) != 0
        && gquic_str_cmp(&src_conn_id, &sess->handshake_dst_conn_id) != 0) {
        goto finished;
    }
    if (gquic_packet_header_deserlialize_type(&rp->data) == GQUIC_LONG_HEADER_0RTT) {
        goto finished;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_unpacker_unpack(&packet,
                                                                   &sess->unpacker,
                                                                   &rp->data, rp->recv_time, GQUIC_STR_SIZE(&rp->dst_conn_id)))) {
        switch (exception) {
        case GQUIC_EXCEPTION_KEY_DROPPED:
            break;
        case GQUIC_EXCEPTION_KEY_UNAVAILABLE:
            was_queued = 1;
            gquic_session_try_queue_undecryptable_packet(sess, rp);
            goto finished;
        case GQUIC_EXCEPTION_INVALID_RESERVED_BITS:
            gquic_session_close_local(sess, exception);
            break;
        }
        goto finished;
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_session_handle_unpacked_packet(sess, &packet, rp->recv_time))) {
        gquic_session_close_local(sess, exception);
        goto finished;
    }
    ret = 1;

finished:
    gquic_unpacked_packet_dtor(&packet);
    if (!was_queued) {
        gquic_packet_buffer_put(buffer);
    }

    return ret;
}

static int gquic_session_handle_retry_packet(gquic_session_t *const sess, const gquic_str_t *const data) {
    int ret = 0;
    gquic_packet_long_header_t *header = NULL;
    gquic_reader_str_t reader = { 0, NULL };
    if (sess == NULL || data == NULL) {
        return 0;
    }
    if (!sess->is_client) {
        return 0;
    }
    if (GQUIC_ASSERT(gquic_packet_long_header_alloc(&header))) {
        return 0;
    }
    reader = *data;
    if (gquic_packet_long_header_deserialize(header, &reader) != 0) {
        ret = 0;
        goto finished;
    }

    gquic_str_t odcid = {
        GQUIC_LONG_HEADER_SPEC(gquic_packet_retry_header_t, header)->odcid_len,
        GQUIC_LONG_HEADER_SPEC(gquic_packet_retry_header_t, header)->odcid
    };
    if (gquic_str_cmp(&odcid, &sess->handshake_dst_conn_id) != 0) {
        ret = 0;
        goto finished;
    }
    gquic_str_t sid = { header->scid_len, header->scid };
    if (gquic_str_cmp(&sid, &sess->handshake_dst_conn_id) == 0) {
        ret = 0;
        goto finished;
    }
    if (sess->received_retry) {
        ret = 0;
        goto finished;
    }
    sess->origin_dst_conn_id = sess->handshake_dst_conn_id;
    gquic_str_t new_dst_conn_id = { 0, NULL };
    gquic_str_copy(&new_dst_conn_id, &sid);
    sess->received_retry = 1;
    if ((ret = gquic_packet_sent_packet_handler_reset_for_retry(&sess->sent_packet_handler)) != 0) {
        gquic_session_close_local(sess, 10 * ret - 2);
        ret = 0;
        goto finished;
    }
    sess->handshake_dst_conn_id = new_dst_conn_id;
    gquic_handshake_establish_change_conn_id(&sess->est, &new_dst_conn_id);

    gquic_str_reset(&sess->packer.token);
    gquic_str_copy(&sess->packer.token, &reader);
    gquic_conn_id_manager_change_initial_conn_id(&sess->conn_id_manager, &new_dst_conn_id);
    gquic_session_schedule_sending(sess);
    ret = 1;
finished:
    gquic_free(header);
    return ret;
}

static int gquic_session_try_queue_undecryptable_packet(gquic_session_t *const sess, gquic_received_packet_t *const rp) {
    int exception = GQUIC_SUCCESS;
    gquic_received_packet_t **rp_storage = NULL;
    if (sess == NULL || rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (sess->handshake_completed) {
        gquic_free(rp);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HANDSHAKE_DONE);
    }
    if (sess->undecryptable_packets_count + 1 > 10) {
        gquic_free(rp);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TOO_MANY_UNDECRYPTABLE_PACKETS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &rp_storage, sizeof(gquic_received_packet_t *)))) {
        gquic_free(rp);
        GQUIC_PROCESS_DONE(exception);
    }
    *rp_storage = rp;
    gquic_list_insert_before(&sess->undecryptable_packets, rp_storage);
    sess->undecryptable_packets_count++;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_unpacked_packet(gquic_session_t *const sess, gquic_unpacked_packet_t *const up, const u_int64_t recv_time) {
    void *frame = NULL;
    int is_ack_eliciting = 0;
    gquic_reader_str_t reader = { 0, NULL };
    if (sess == NULL || up == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&up->data) == 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (sess->is_client && !sess->received_first_packet && up->hdr.is_long) {
        gquic_str_t src_conn_id = { up->hdr.hdr.l_hdr->scid_len, up->hdr.hdr.l_hdr->scid };
        if (gquic_str_cmp(&src_conn_id, &sess->handshake_dst_conn_id) != 0) {
            gquic_str_reset(&sess->handshake_dst_conn_id);
            gquic_str_init(&sess->handshake_dst_conn_id);
            gquic_str_copy(&sess->handshake_dst_conn_id, &src_conn_id);
            gquic_conn_id_manager_change_initial_conn_id(&sess->conn_id_manager, &sess->handshake_dst_conn_id);
        }
    }
    sess->received_first_packet = 1;
    sess->last_packet_received_time = recv_time;
    sess->first_ack_eliciting_packet = 0;
    sess->keep_alive_ping_sent = 0;

    reader = up->data;
    for ( ;; ) {
        if (GQUIC_STR_SIZE(&reader) == 0) {
            break;
        }
        frame = NULL;
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_parser_next(&frame, &sess->frame_parser, &reader, up->enc_lv));
        if (frame == NULL) {
            break;
        }
        if (GQUIC_FRAME_META(frame).type != 0x02 && GQUIC_FRAME_META(frame).type != 0x03) {
            is_ack_eliciting = 1;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_session_handle_frame(sess, frame, up->enc_lv));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_received_packet_handlers_received_packet(&sess->recv_packet_handler,
                                                                                   up->pn, recv_time, is_ack_eliciting, up->enc_lv));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_frame(gquic_session_t *const sess, void *const frame, const u_int8_t enc_lv) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (GQUIC_FRAME_META(frame).type) {
    case 0x06:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_crypto_frame(sess, frame, enc_lv));
        break;
    case 0x02:
    case 0x03:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_ack_frame(sess, frame, enc_lv));
        break;
    case 0x1c:
    case 0x1d:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_connection_close_frame(sess, frame));
        break;
    case 0x04:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_reset_stream_frame(sess, frame));
        break;
    case 0x10:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_max_data_frame(sess, frame));
        break;
    case 0x12:
    case 0x13:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_max_streams_frame(sess, frame));
        break;
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x01:
    case 0x1b:
        // TODO proccess these frames
        break;
    case 0x05:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_stop_sending_frame(sess, frame));
        break;
    case 0x1a:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_path_challenge_frame(sess, frame));
        break;
    case 0x07:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_new_token_frame(sess, frame));
        break;
    case 0x18:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_new_conn_id_frame(sess, frame));
        break;
    case 0x19:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_retire_conn_id_frame(sess, frame));
        break;
    case 0x1e:
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_handshake_done_frame(sess, frame));
        break;
    default:
        if ((GQUIC_FRAME_META(frame).type & 0x08) != 0) {
            GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_handle_stream_frame(sess, frame));
        }
        else {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_FRAME_TYPE_UNEXCEPTED);
        }
    }

    gquic_frame_release(frame);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_session_handle_stream_frame(gquic_session_t *const sess, gquic_frame_stream_t *const frame) {
    gquic_stream_t *str = NULL;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle stream frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_stream_map_get_or_open_recv_stream(&str, &sess->streams_map, frame->id));
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_recv_stream_handle_stream_frame(&str->recv, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_crypto_frame(gquic_session_t *const sess, gquic_frame_crypto_t *const frame, const u_int8_t enc_lv) {
    int changed = 0;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle crypto frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_crypto_stream_manager_handle_crypto_frame(&changed, &sess->crypto_stream_manager, frame, enc_lv));

    if (changed) {
        gquic_session_try_decrypting_queued_packets(sess);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_connection_close_frame(gquic_session_t *const sess, gquic_frame_connection_close_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle connection close frame");

    if (GQUIC_FRAME_META(frame).type == 0x1d) {
        // app err
        gquic_session_close_remote(sess, frame->errcode);
    }
    else {
        // conn err
        gquic_session_close_remote(sess, frame->errcode);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_try_decrypting_queued_packets(gquic_session_t *const sess) {
    gquic_received_packet_t **rp_storage = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LIST_FOREACH(rp_storage, &sess->undecryptable_packets) {
        gquic_session_handle_packet(sess, *rp_storage);
    }
    while (!gquic_list_head_empty(&sess->undecryptable_packets)) {
        gquic_list_release(GQUIC_LIST_FIRST(&sess->undecryptable_packets));
        sess->undecryptable_packets_count--;
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_ack_frame(gquic_session_t *const sess, gquic_frame_ack_t *const frame, const u_int8_t enc_lv) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle ack frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_packet_sent_packet_handler_received_ack(&sess->sent_packet_handler,
                                                                           frame, enc_lv, sess->last_packet_received_time));
    if (enc_lv == GQUIC_ENC_LV_1RTT) {
        gquic_packet_received_packet_handlers_ignore_below(&sess->recv_packet_handler, sess->sent_packet_handler.lowest_not_confirm_acked);
        sess->est.aead.last_ack_pn = frame->largest_ack;
    }

    liteco_channel_send(&sess->ack_chan, &sess->ack_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_reset_stream_frame(gquic_session_t *const sess, gquic_frame_reset_stream_t *const frame) {
    gquic_stream_t *str = NULL;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle reset stream frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_stream_map_get_or_open_recv_stream(&str, &sess->streams_map, frame->id));
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_stream_handle_reset_stream_frame(str, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_max_data_frame(gquic_session_t *const sess, gquic_frame_max_data_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle max data frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_flowcontrol_base_update_swnd(&sess->conn_flow_ctrl.base, frame->max));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_max_stream_data_frame(gquic_session_t *const sess, gquic_frame_max_stream_data_t *const frame) {
    gquic_stream_t *str = NULL;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_stream_map_get_or_open_send_stream(&str, &sess->streams_map, frame->id));
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_send_stream_handle_max_stream_data_frame(&str->send, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_max_streams_frame(gquic_session_t *const sess, gquic_frame_max_streams_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle max streams frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_stream_map_handle_max_streams_frame(&sess->streams_map, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_stop_sending_frame(gquic_session_t *const sess, gquic_frame_stop_sending_t *const frame) {
    gquic_stream_t *str = NULL;
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle stop sending frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_stream_map_get_or_open_send_stream(&str, &sess->streams_map, frame->id));
    if (str == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_send_stream_handle_stop_sending_frame(&str->send, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_path_challenge_frame(gquic_session_t *const sess, gquic_frame_path_challenge_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle path challenge frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_session_queue_control_frame(sess, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_new_token_frame(gquic_session_t *const sess, gquic_frame_new_token_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle new token frame");

    if (!sess->is_client) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ASPECT_ERROR);
    }
    // TODO token store

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_new_conn_id_frame(gquic_session_t *const sess, gquic_frame_new_connection_id_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle new connection id frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_manager_add(&sess->conn_id_manager, frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_retire_conn_id_frame(gquic_session_t *const sess, gquic_frame_retire_connection_id_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle retire connection id frame");

    GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_gen_retire(&sess->conn_id_gen, frame->seq));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_handshake_done_frame(gquic_session_t *const sess, gquic_frame_handshake_done_t *const frame) {
    if (sess == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "session handle handshake done frame");
    if (!sess->is_client) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_FRAME);
    }

    gquic_handshake_establish_drop_handshake_keys(&sess->est);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_close_remote(gquic_session_t *const sess, const int err) {
    int exception = GQUIC_SUCCESS;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&sess->close_mtx);
    if (sess->close_flag) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    sess->close_flag = 1;
    gquic_session_close_event_t *event = NULL;
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&event, gquic_session_close_event_t))) {
        pthread_mutex_unlock(&sess->close_mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    event->err = err;
    event->immediate = 1;
    event->remote = 1;
    pthread_mutex_unlock(&sess->close_mtx);

    liteco_channel_send(&sess->close_chain, event);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_close_err(gquic_session_t *const sess, const int err, const int immediate, const int remote) {
    __gquic_session_handle_close_err_local_params_t params;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (remote) {
        gquic_conn_id_gen_replace_with_closed(&sess->conn_id_gen,
                                              gquic_session_handle_close_err_remote_alloc_closed_session,
                                              sess);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (immediate) {
        gquic_conn_id_gen_remove_all(&sess->conn_id_gen);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    params.sess = sess;
    gquic_str_init(&params.close_packet);
    gquic_session_send_connection_close(&params.close_packet, sess, err, 0, 0, NULL);
    gquic_conn_id_gen_replace_with_closed(&sess->conn_id_gen,
                                          gquic_session_handle_close_err_local_alloc_closed_session,
                                          &params);

    gquic_str_reset(&params.close_packet);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_send_connection_close(gquic_str_t *const data,
                                               gquic_session_t *const sess,
                                               const int is_app, const u_int64_t errcode, const u_int64_t frame_type, const gquic_str_t *const reason) {
    gquic_packed_packet_t packet;
    gquic_frame_connection_close_t *frame = NULL;
    if (data == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packed_packet_init(&packet);
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_connection_close_alloc(&frame));
    GQUIC_FRAME_META(frame).type = is_app ? 0x1d : 0x1c;
    frame->errcode = errcode;
    frame->type = frame_type;
    frame->phase_len = GQUIC_STR_SIZE(reason);
    frame->phase = GQUIC_STR_VAL(reason);

    gquic_packet_packer_pack_conn_close(&packet, &sess->packer, frame);
    gquic_str_copy(data, &packet.raw);
    gquic_packed_packet_dtor(&packet);
    gquic_net_conn_write(sess->conn, data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_send_packets(gquic_session_t *const sess) {
    u_int8_t send_mode = 0x00;
    u_int64_t packets_count = 0;
    u_int64_t packets_sent_count = 0;
    int sended = 0;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sess->pacing_deadline = 0;
    send_mode = gquic_packet_sent_packet_handler_send_mode(&sess->sent_packet_handler);
    if (send_mode == GQUIC_SEND_MODE_NONE) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    packets_count = gquic_packet_sent_packet_handler_should_send_packets_count(&sess->sent_packet_handler);

    for ( ;; ) {
        GQUIC_LOG(GQUIC_LOG_DEBUG, "session send packets loop");
        sended = 0;
        switch (send_mode) {
        case GQUIC_SEND_MODE_NONE:
            goto loop_end;

        case GQUIC_SEND_MODE_ACK:
            if (packets_sent_count > 0) {
                GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
            }
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session send mode ack");

            GQUIC_ASSERT_FAST_RETURN(gquic_session_try_send_only_ack_packet(sess));
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);

        case GQUIC_SEND_MODE_PTO_INITIAL:
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session send initial packet (PTO)");

            GQUIC_ASSERT_FAST_RETURN(gquic_session_send_probe_packet(sess, GQUIC_ENC_LV_INITIAL));
            packets_sent_count++;
            break;

        case GQUIC_SEND_MODE_PTO_HANDSHAKE:
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session send handshake packet (PTO)");

            GQUIC_ASSERT_FAST_RETURN(gquic_session_send_probe_packet(sess, GQUIC_ENC_LV_HANDSHAKE));
            packets_sent_count++;
            break;

        case GQUIC_SEND_MODE_PTO_APP:
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session send app packet (PTO)");

            GQUIC_ASSERT_FAST_RETURN(gquic_session_send_probe_packet(sess, GQUIC_ENC_LV_1RTT));
            packets_sent_count++;
            break;

        case GQUIC_SEND_MODE_ANY:
            GQUIC_LOG(GQUIC_LOG_DEBUG, "session send any packet");

            GQUIC_ASSERT_FAST_RETURN(gquic_session_send_packet(&sended, sess));
            if (!sended) {
                goto loop_end;
            }
            packets_sent_count++;
            break;

        default:
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_SEND_MODE);
        }
        if (packets_sent_count >= packets_count) {
            break;
        }
        send_mode = gquic_packet_sent_packet_handler_send_mode(&sess->sent_packet_handler);
    }

loop_end:
    if (packets_sent_count == packets_count) {
        sess->pacing_deadline = sess->sent_packet_handler.next_send_time;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_try_send_only_ack_packet(gquic_session_t *const sess) {
    int exception = GQUIC_SUCCESS;
    GQUIC_CPTR_TYPE(gquic_packet_t) packet = NULL;
    gquic_packed_packet_t *packed_packet = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ALLOC(exception, &packet, gquic_cptr_packet_t, packet, cptr, gquic_cptr_packet_dtor);
    GQUIC_ASSERT_FAST_RETURN(exception);
    if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&packed_packet, gquic_packed_packet_t))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_packet_init(packet);
    gquic_packed_packet_init(packed_packet);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_try_pack_ack_packet(packed_packet, &sess->packer))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(exception);
    }
    if (!packed_packet->valid) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packed_packet_get_ack_packet(packet, packed_packet, &sess->retransmission))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_sent_packet_handler_sent_packet(&sess->sent_packet_handler, packet))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(exception);
    }
    gquic_session_send_packed_packet(sess, packed_packet);

    GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_send_packed_packet(gquic_session_t *const sess, gquic_packed_packet_t *const packed_packet) {
    if (sess == NULL || packed_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (sess->first_ack_eliciting_packet == 0 && gquic_packed_packet_is_ack_eliciting(packed_packet)) {
        sess->first_ack_eliciting_packet = gquic_time_now();
    }
    sess->conn_id_manager.packets_count_since_last_change++;

    gquic_packet_send_queue_send(&sess->send_queue, packed_packet);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_send_packet(int *const sent_packet, gquic_session_t *const sess) {
    int exception = GQUIC_SUCCESS;
    u_int64_t swnd = 0;
    gquic_frame_data_blocked_t *blocked = NULL;
    gquic_packed_packet_t *packed_packet = NULL;
    GQUIC_CPTR_TYPE(gquic_packet_t) packet = NULL;
    if (sent_packet == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *sent_packet = 0;
    if (gquic_flowcontrol_base_is_newly_blocked(&swnd, &sess->conn_flow_ctrl.base)) {
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_data_blocked_alloc(&blocked));
        blocked->limit = swnd;
        gquic_framer_queue_ctrl_frame(&sess->framer, blocked);
    }

    GQUIC_ASSERT(gquic_wnd_update_queue_queue_all(&sess->wnd_update_queue));

    GQUIC_CPTR_ALLOC(exception, &packet, gquic_cptr_packet_t, packet, cptr, gquic_cptr_packet_dtor);
    GQUIC_ASSERT_FAST_RETURN(exception);
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&packed_packet, gquic_packed_packet_t))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        GQUIC_PROCESS_DONE(exception);
    }
    gquic_packet_init(packet);
    gquic_packed_packet_init(packed_packet);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_pack_packet(packed_packet, &sess->packer))) {
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(exception);
    }
    if (!packed_packet->valid) {
        GQUIC_LOG(GQUIC_LOG_DEBUG, "session packet invalid packet");

        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    gquic_packed_packet_get_ack_packet(packet, packed_packet, &sess->retransmission);
    gquic_packet_sent_packet_handler_sent_packet(&sess->sent_packet_handler, packet);
    gquic_session_send_packed_packet(sess, packed_packet);
    *sent_packet = 1;

    GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_send_probe_packet(gquic_session_t *const sess, const u_int8_t enc_lv) {
    int exception = GQUIC_SUCCESS;
    gquic_packed_packet_t *packed_packet = NULL;
    GQUIC_CPTR_TYPE(gquic_packet_t) packet = NULL;
    gquic_frame_ping_t *ping = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&packed_packet, gquic_packed_packet_t));
    for ( ;; ) {
        gquic_packed_packet_init(packed_packet);
        if (!gquic_packet_sent_packet_handler_queue_probe_packet(&sess->sent_packet_handler, enc_lv)) {
            break;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_try_pack_probe_packet(packed_packet, &sess->packer, enc_lv))) {
            gquic_free(packed_packet);
            GQUIC_PROCESS_DONE(exception);
        }
        if (packed_packet->valid) {
            break;
        }
        gquic_packed_packet_dtor(packed_packet);
    }

    if (!packed_packet->valid) {
        gquic_packed_packet_dtor(packed_packet);
        gquic_packed_packet_init(packed_packet);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_ping_alloc(&ping))) {
            gquic_free(packed_packet);
            GQUIC_PROCESS_DONE(exception);
        }
        switch (enc_lv) {
        case GQUIC_ENC_LV_INITIAL:
            gquic_retransmission_queue_add_initial(&sess->retransmission, ping);
            break;
        case GQUIC_ENC_LV_HANDSHAKE:
            gquic_retransmission_queue_add_handshake(&sess->retransmission, ping);
            break;
        case GQUIC_ENC_LV_1RTT:
            gquic_retransmission_queue_add_app(&sess->retransmission, ping);
            break;
        default:
            gquic_free(packed_packet);
            gquic_frame_release(ping);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_packer_try_pack_probe_packet(packed_packet, &sess->packer, enc_lv))) {
            gquic_packed_packet_dtor(packed_packet);
            gquic_free(packed_packet);
            GQUIC_PROCESS_DONE(exception);
        }
    }
    if (!packed_packet->valid) {
        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PACKED_PACKET_INVALID);
    }

    GQUIC_CPTR_ALLOC(exception, &packet, gquic_cptr_packet_t, packet, cptr, gquic_cptr_packet_dtor);
    if (GQUIC_ASSERT(exception)) {
        gquic_packed_packet_dtor(packed_packet);
        gquic_free(packed_packet);
        GQUIC_PROCESS_DONE(exception);
    }
    gquic_packed_packet_get_ack_packet(packet, packed_packet, &sess->retransmission);
    gquic_packet_sent_packet_handler_sent_packet(&sess->sent_packet_handler, packet);
    gquic_session_send_packed_packet(sess, packed_packet);

    GQUIC_CPTR_TRY_RELEASE(exception, packet, gquic_cptr_packet_t, packet, cptr);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_close_err_remote_alloc_closed_session(gquic_packet_handler_t **const handler_storage, void *const sess_) {
    gquic_session_t *const sess = sess_;
    if (handler_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (sess->is_client) {
        gquic_closed_remote_session_client_alloc(handler_storage);
    }
    else {
        gquic_closed_remote_session_server_alloc(handler_storage);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_session_handle_close_err_local_alloc_closed_session(gquic_packet_handler_t **const handler_storage, void *const params_) {
    __gquic_session_handle_close_err_local_params_t *const params = params_;
    if (params == NULL || handler_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(gquic_closed_local_session_alloc(handler_storage, params->sess->conn, &params->close_packet, params->sess->is_client));
}

static int gquic_session_config_transfer_tls_config(gquic_tls_config_t *const tls_config, gquic_config_t *const config) {
    if (tls_config == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_copy(&tls_config->next_protos, &config->next_protos, NULL);
    tls_config->enforce_next_proto_selection = config->enforce_next_proto_selections;
    tls_config->verify_peer_certs = config->verify_peer_certs;
    tls_config->get_ser_cert = config->get_ser_cert;
    tls_config->get_cli_cert = config->get_cli_cert;
    tls_config->insecure_skiy_verify = config->insecure_skiy_verify;
    gquic_list_copy(&tls_config->cipher_suites, &config->cipher_suites, NULL);
    tls_config->ser_perfer_cipher_suite = config->ser_perfer_cipher_suite;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

// maybe other thread
int gquic_session_accept_stream(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_accept_stream(stream_storage, &sess->streams_map, &sess->done_chain));
}

int gquic_session_accept_uni_stream(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_accept_uni_stream(stream_storage, &sess->streams_map, &sess->done_chain));
}

int gquic_session_open_stream(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_open_stream(stream_storage, &sess->streams_map));
}

int gquic_session_open_stream_sync(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_open_stream_sync(stream_storage, &sess->streams_map, &sess->done_chain));
}

int gquic_session_open_uni_stream(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_open_uni_stream(stream_storage, &sess->streams_map));
}

int gquic_session_open_uni_stream_sync(gquic_stream_t **const stream_storage, gquic_session_t *const sess) {
    if (stream_storage == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_stream_map_open_uni_stream_sync(stream_storage, &sess->streams_map, &sess->done_chain));
}

gquic_exception_t gquic_session_waiting_acked_all(gquic_session_t *const sess) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    const liteco_channel_t *recv_channel = NULL;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    for ( ;; ) {
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, 0, &sess->ack_chan, &sess->done_chain, &sess->close_chain);

        if (gquic_packet_sent_packet_handler_acked_all(&sess->sent_packet_handler)) {
            break;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

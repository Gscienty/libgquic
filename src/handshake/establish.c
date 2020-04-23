#include "handshake/establish.h"
#include "handshake/initial_aead.h"
#include "tls/alert.h"
#include "util/malloc.h"
#include "exception.h"
#include "global_schedule.h"
#include <pthread.h>

static int __establish_run(gquic_coroutine_t *const, void *const);
static int gquic_establish_check_enc_level(const u_int8_t, const u_int8_t);
static int gquic_establish_waiting_handshake_done_cmp(const void *const, const void *const);
static int gquic_establish_cli_handle_msg(gquic_handshake_establish_t *const, gquic_coroutine_t *const, const u_int8_t);
static int gquic_establish_ser_handle_msg(gquic_handshake_establish_t *const, gquic_coroutine_t *const, const u_int8_t);
static int gquic_establish_waiting_ser_handle_cmp(const void *const, const void *const);
static int gquic_establish_drop_initial_keys_wrap(void *const);

static int gquic_establish_record_layer_read_handshake_msg_wrap(gquic_str_t *const, void *const, gquic_coroutine_t *const);
static int gquic_establish_record_layer_set_rkey(void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
static int gquic_establish_record_layer_set_wkey(void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
static int gquic_establish_record_layer_write_record(size_t *const, void *const, const gquic_str_t *const);
static int gquic_establish_record_layer_send_alert(void *const, const u_int8_t);

static int gquic_establish_handle_post_handshake_msg(gquic_handshake_establish_t *const, gquic_coroutine_t *const);

static int gquic_establish_try_send_sess_ticket(gquic_handshake_establish_t *const);

int gquic_handshake_event_init(gquic_handshake_event_t *const event) {
    if (event == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    event->on_recv_params.cb = NULL;
    event->on_recv_params.self = NULL;
    event->on_err.cb = NULL;
    event->on_err.self = NULL;
    event->drop_keys.cb = NULL;
    event->drop_keys.self = NULL;
    event->on_handshake_complete.cb = NULL;
    event->on_handshake_complete.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_init(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    est->cfg = NULL;
    gquic_tls_conn_init(&est->conn);
    gquic_handshake_event_init(&est->events);
    gquic_coroutine_chain_init(&est->err_chain);
    gquic_coroutine_chain_init(&est->msg_chain);
    gquic_coroutine_chain_init(&est->param_chain);
    gquic_coroutine_chain_init(&est->done_chain);
    gquic_coroutine_chain_init(&est->complete_chain);
    gquic_coroutine_chain_init(&est->close_chain);
    gquic_coroutine_chain_init(&est->alert_chain);
    gquic_coroutine_chain_init(&est->write_record_chain);
    gquic_coroutine_chain_init(&est->received_rkey_chain);
    gquic_coroutine_chain_init(&est->received_wkey_chain);
    est->cli_hello_written = 0;
    est->is_client = 0;
    sem_init(&est->client_written_sem, 0, 0);
    sem_init(&est->mtx, 0, 1);
    est->read_enc_level = GQUIC_ENC_LV_INITIAL;
    est->write_enc_level = GQUIC_ENC_LV_INITIAL;
    gquic_io_init(&est->init_output);
    gquic_common_long_header_opener_init(&est->initial_opener);
    gquic_common_long_header_sealer_init(&est->initial_sealer);
    gquic_io_init(&est->handshake_output);
    gquic_common_long_header_opener_init(&est->handshake_opener);
    gquic_common_long_header_sealer_init(&est->handshake_sealer);
    gquic_io_init(&est->one_rtt_output);
    gquic_auto_update_aead_init(&est->aead);
    est->has_1rtt_sealer = 0;
    est->has_1rtt_opener = 0;

    gquic_handshake_extension_handler_init(&est->extension_handler);

    est->handshake_done = 0;
    sem_init(&est->handshake_done_notify, 0, 0);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_dtor(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    
    // TODO

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_ctor(gquic_handshake_establish_t *const est,
                                   void *initial_stream_self,
                                   int (*initial_stream_cb) (void *const, gquic_writer_str_t *const),
                                   void *handshake_stream_self,
                                   int (*handshake_stream_cb) (void *const, gquic_writer_str_t *const),
                                   void *one_rtt_self,
                                   int (*one_rtt_cb) (void *const, gquic_writer_str_t *const),
                                   void *chello_written_self,
                                   int (*chello_written_cb) (void *const),
                                   gquic_tls_config_t *const cfg,
                                   const gquic_str_t *const conn_id,
                                   const gquic_transport_parameters_t *const params,
                                   gquic_rtt_t *const rtt,
                                   const gquic_net_addr_t *const addr,
                                   const int is_client) {
    if (est == NULL || conn_id == NULL || params == NULL || cfg == NULL || rtt == NULL || addr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_extension_handler_ctor(&est->extension_handler, &est->param_chain, params, is_client));

    gquic_handshake_extension_handler_set_config_extension(cfg, &est->extension_handler);
    gquic_handshake_establish_set_record_layer(&cfg->alt_record, est);

    gquic_common_long_header_sealer_init(&est->initial_sealer);
    gquic_common_long_header_opener_init(&est->initial_opener);
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_initial_aead_init(&est->initial_sealer, &est->initial_opener, conn_id, is_client));

    gquic_io_writer_implement(&est->init_output, initial_stream_self, initial_stream_cb);
    gquic_io_writer_implement(&est->handshake_output, handshake_stream_self, handshake_stream_cb);
    gquic_io_writer_implement(&est->one_rtt_output, one_rtt_self, one_rtt_cb);

    est->aead.rtt = rtt;
    est->cfg = cfg;
    est->is_client = is_client;
    est->conn.addr = addr;
    est->conn.cfg = cfg;
    est->conn.is_client = is_client;
    est->conn.ver = GQUIC_TLS_VERSION_13;

    est->chello_written.cb = chello_written_cb;
    est->chello_written.self = chello_written_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_change_conn_id(gquic_handshake_establish_t *const est,
                                             const gquic_str_t *const conn_id) {
    if (est == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_common_long_header_sealer_dtor(&est->handshake_sealer);
    gquic_common_long_header_sealer_init(&est->handshake_sealer);
    gquic_common_long_header_opener_dtor(&est->handshake_opener);
    gquic_common_long_header_opener_init(&est->handshake_opener);
    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_initial_aead_init(&est->handshake_sealer, &est->handshake_opener, conn_id, est->is_client));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_1rtt_set_last_acked(gquic_handshake_establish_t *const est, const u_int64_t pn) {
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    est->aead.last_ack_pn = pn;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_run(gquic_coroutine_t *const co, gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    gquic_establish_ending_event_t *ending_event = NULL;
    void *ending = NULL;
    gquic_establish_err_event_t *err_event = NULL;
    gquic_coroutine_t *establish_run_co = NULL;
    if (co == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_alloc(&establish_run_co));
    gquic_coroutine_ctor(establish_run_co, 1024 * 1024, __establish_run, est);
    gquic_coroutine_schedule_join(gquic_get_global_schedule(), establish_run_co);
    GQUIC_EXCEPTION_ASSIGN(exception,
                           gquic_coroutine_chain_recv(&ending, co, 1,
                                                      &est->alert_chain, &est->complete_chain, &est->close_chain, NULL));
    if (exception == GQUIC_EXCEPTION_CLOSED) {
        if (ending == &est->complete_chain) {
            GQUIC_HANDSHAKE_EVENT_ON_HANDSHAKE_COMPLETE(&est->events);
            if (!est->is_client) {
                gquic_establish_try_send_sess_ticket(est);
            }
        }
        else if (ending == &est->close_chain) {
            gquic_coroutine_chain_boradcast_close(&est->msg_chain, gquic_get_global_schedule());
            gquic_coroutine_chain_recv(&ending, co, 1, &est->done_chain, NULL);
        }
    }
    else {
        // alert
        ending_event = ending;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_coroutine_chain_recv((void **) &err_event, co, 1, est->err_chain, NULL))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, ending_event->payload.alert_code, err_event->ret))) {
            goto failure;
        }
    }
    est->handshake_done = 1;
    sem_post(&est->handshake_done_notify);

    if (ending_event != NULL) {
        gquic_list_release(ending_event);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ending_event != NULL) {
        gquic_list_release(ending_event);
    }
    GQUIC_PROCESS_DONE(exception);
}

static int __establish_run(gquic_coroutine_t *const co, void *const est_) {
    (void) co;
    gquic_handshake_establish_t *const est = est_;
    int exception = GQUIC_SUCCESS;
    gquic_establish_err_event_t *err_event = NULL;
    if (est == NULL) {
        goto finish;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_handshake(&est->conn, co))) {
        if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&err_event, gquic_establish_err_event_t))) {
            goto finish;
        }
        err_event->ret = exception;
        gquic_coroutine_chain_send(&est->err_chain, gquic_get_global_schedule(), err_event);
        gquic_coroutine_chain_boradcast_close(&est->close_chain, gquic_get_global_schedule());
        goto finish;
    }
    gquic_coroutine_chain_boradcast_close(&est->complete_chain, gquic_get_global_schedule());
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
finish:
    gquic_coroutine_chain_boradcast_close(&est->done_chain, gquic_get_global_schedule());
    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_close(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_chain_boradcast_close(&est->close_chain, gquic_get_global_schedule());

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_handle_msg(gquic_handshake_establish_t *const est,
                                         gquic_coroutine_t *const co, const gquic_str_t *const data, const u_int8_t enc_level) {
    int exception = GQUIC_SUCCESS;
    u_int8_t type = 0;
    if (est == NULL || co == NULL || GQUIC_STR_SIZE(data) == 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    type = GQUIC_STR_FIRST_BYTE(data);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_establish_check_enc_level(type, enc_level))) {
        GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE, exception);
        return 0;
    }
    gquic_coroutine_chain_send(&est->msg_chain, gquic_get_global_schedule(), (void *) data);
    if (enc_level == GQUIC_ENC_LV_1RTT) {
        gquic_establish_handle_post_handshake_msg(est, co);
    }

    if (est->is_client) {
        return gquic_establish_cli_handle_msg(est, co, type);
    }
    else {
        return gquic_establish_ser_handle_msg(est, co, type);
    }
}

static int gquic_establish_check_enc_level(const u_int8_t msg_type, const u_int8_t enc_level) {
    u_int8_t expect = 0;
    switch (msg_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        expect = GQUIC_ENC_LV_INITIAL;
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        expect = GQUIC_ENC_LV_HANDSHAKE;
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        expect = GQUIC_ENC_LV_1RTT;
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HANDSHAKE_TYPE_UNEXCEPTED);
    }
    if (expect != enc_level) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ENC_LV_INCONSISTENT);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_establish_waiting_handshake_done_cmp(const void *const a, const void *const b) {
    (void) b;
    if (a == NULL) {
        return -1;
    }
    if (((gquic_establish_process_event_t *) a)->type != GQUIC_ESTABLISH_PROCESS_EVENT_DONE) {
        return 1;
    }

    return 0;
}

static int gquic_establish_cli_handle_msg(gquic_handshake_establish_t *const est, gquic_coroutine_t *const co, const u_int8_t msg_type) {
    void *event = NULL;
    if (est == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (msg_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->write_record_chain, &est->received_wkey_chain, NULL);
        if (event == &est->done_chain || event == &est->write_record_chain) {
            return 0;
        }
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->received_rkey_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        return 1;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->param_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(&est->events, &((gquic_establish_process_event_t *) event)->param);
        gquic_str_reset(&((gquic_establish_process_event_t *) event)->param);
        free(event);
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->received_rkey_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->received_wkey_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static int gquic_establish_ser_handle_msg(gquic_handshake_establish_t *const est, gquic_coroutine_t *const co, const u_int8_t msg_type) {
    void *event = NULL;
    if (est == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (msg_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->write_record_chain, &est->param_chain, NULL);
        if (event == &est->done_chain || event == &est->write_record_chain) {
            return 0;
        }
        GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(&est->events, &((gquic_establish_process_event_t *) event)->param);
        gquic_str_reset(&((gquic_establish_process_event_t *) event)->param);
        free(event);

ignore_shello:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->write_record_chain, &est->received_rkey_chain, NULL);
        if (event == &est->write_record_chain) {
            goto ignore_shello;
        }
        if (event == &est->done_chain) {
            return 0;
        }

ignore_ext:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->write_record_chain, &est->received_wkey_chain, NULL);
        if (event == &est->write_record_chain) {
            goto ignore_ext;
        }
        if (event == &est->done_chain) {
            return 0;
        }

        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->received_wkey_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        return 1;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        gquic_coroutine_chain_recv(&event, co, 1, &est->done_chain, &est->received_rkey_chain, NULL);
        if (event == &est->done_chain) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static int gquic_establish_waiting_ser_handle_cmp(const void *const event, const void *const type) {
    const gquic_establish_process_event_t *process_event = event;
    if (event == NULL || type == NULL) {
        return -1;
    }

    switch (*(u_int8_t *) type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        if (process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_PARAM
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_DONE
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY) {
            return 0;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        if (process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_DONE) {
            return 0;
        }
        break;
    }
    return 1;
}

int gquic_handshake_establish_read_handshake_msg(gquic_str_t *const msg, gquic_handshake_establish_t *const est, gquic_coroutine_t *const co) {
    gquic_str_t *tmp = NULL;
    if (msg == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_recv((void **) &tmp, co, 1, &est->msg_chain, NULL));
    *msg = *tmp;
    free(tmp);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_set_rkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec) {
    int exception = GQUIC_SUCCESS;
    if (est == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    switch (enc_level) {
    case GQUIC_ENC_LV_HANDSHAKE:
        est->read_enc_level = GQUIC_ENC_LV_HANDSHAKE;
        gquic_common_long_header_opener_dtor(&est->handshake_opener);
        gquic_common_long_header_opener_init(&est->handshake_opener);
        gquic_common_long_header_opener_handshake_traffic_ctor(&est->handshake_opener,
                                                               suite,
                                                               traffic_sec,
                                                               est,
                                                               gquic_establish_drop_initial_keys_wrap,
                                                               est->is_client);
        break;

    case GQUIC_ENC_LV_APP:
        est->read_enc_level = GQUIC_ENC_LV_1RTT;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_auto_update_aead_set_rkey(&est->aead, suite, traffic_sec))) {
            goto failure;
        }
        est->has_1rtt_opener = 1;
        break;

    default:
        sem_post(&est->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    sem_post(&est->mtx);
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_send(&est->received_rkey_chain, gquic_get_global_schedule(), &est->received_rkey_chain));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    sem_post(&est->mtx);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_set_wkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec) {
    int exception = GQUIC_SUCCESS;
    if (est == NULL || suite == NULL || traffic_sec == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    switch (enc_level) {
    case GQUIC_ENC_LV_HANDSHAKE:
        est->write_enc_level = GQUIC_ENC_LV_HANDSHAKE;
        gquic_common_long_header_sealer_dtor(&est->handshake_sealer);
        gquic_common_long_header_sealer_init(&est->handshake_sealer);
        gquic_common_long_header_sealer_handshake_traffic_ctor(&est->handshake_sealer,
                                                               suite,
                                                               traffic_sec,
                                                               est,
                                                               gquic_establish_drop_initial_keys_wrap,
                                                               est->is_client);
        break;

    case GQUIC_ENC_LV_APP:
        est->write_enc_level = GQUIC_ENC_LV_1RTT;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_auto_update_aead_set_wkey(&est->aead, suite, traffic_sec))) {
            goto failure;
        }
        est->has_1rtt_sealer = 1;
        break;

    default:
        sem_post(&est->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    sem_post(&est->mtx);
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_send(&est->received_wkey_chain, gquic_get_global_schedule(), &est->received_wkey_chain));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    sem_post(&est->mtx);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_drop_initial_keys(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    gquic_common_long_header_opener_dtor(&est->initial_opener);
    gquic_common_long_header_sealer_dtor(&est->initial_sealer);
    sem_post(&est->mtx);
    GQUIC_HANDSHAKE_EVENT_DROP_KEYS(&est->events, GQUIC_ENC_LV_INITIAL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_drop_handshake_keys(gquic_handshake_establish_t *const est) {
    int dropped = 0;
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (est->handshake_opener.available) {
        gquic_common_long_header_opener_dtor(&est->handshake_opener);
        gquic_common_long_header_sealer_dtor(&est->handshake_sealer);
        dropped = 1;
    }
    sem_post(&est->mtx);
    if (dropped) {
        GQUIC_HANDSHAKE_EVENT_DROP_KEYS(&est->events, GQUIC_ENC_LV_HANDSHAKE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_establish_drop_initial_keys_wrap(void *const est) {
    return gquic_handshake_establish_drop_initial_keys(est);
}

int gquic_handshake_establish_write_record(size_t *const size, gquic_handshake_establish_t *const est, const gquic_str_t *const data) {
    int exception = GQUIC_SUCCESS;
    if (size == NULL || est == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    gquic_writer_str_t writer = *data;
    switch (est->write_enc_level) {
    case GQUIC_ENC_LV_INITIAL:
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_IO_WRITE(&est->init_output, &writer))) {
            goto failure;
        }
        if (!est->cli_hello_written && est->is_client) {
            est->cli_hello_written = 1;
            if (est->chello_written.self == NULL) {
                sem_post(&est->client_written_sem);
            }
            else {
                GQUIC_HANDSHAKE_ESTABLISH_CHELLO_WRITTEN(est);
            }
        }
        else {
            if (GQUIC_ASSERT_CAUSE(exception,
                                   gquic_coroutine_chain_send(&est->write_record_chain, gquic_get_global_schedule(), &est->write_record_chain))) {
                goto failure;
            }
        }
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_IO_WRITE(&est->handshake_output, &writer))) {
            goto failure;
        }
        break;
    default:
        sem_post(&est->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }
    sem_post(&est->mtx);
    *size = GQUIC_STR_VAL(&writer) - GQUIC_STR_VAL(data);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    sem_post(&est->mtx);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_send_alert(gquic_handshake_establish_t *const est, const u_int8_t alert) {
    gquic_establish_ending_event_t *ending_event = NULL;
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&ending_event, gquic_establish_ending_event_t));
    ending_event->type = GQUIC_ESTABLISH_ENDING_EVENT_ALERT;
    ending_event->payload.alert_code = alert;
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_chain_send(&est->alert_chain, gquic_get_global_schedule(), ending_event));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_set_record_layer(gquic_tls_record_layer_t *const record_layer, gquic_handshake_establish_t *const est) {
    if (record_layer == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    record_layer->self = est;
    record_layer->read_handshake_msg = gquic_establish_record_layer_read_handshake_msg_wrap;
    record_layer->set_rkey = gquic_establish_record_layer_set_rkey;
    record_layer->set_wkey = gquic_establish_record_layer_set_wkey;
    record_layer->write_record = gquic_establish_record_layer_write_record;
    record_layer->send_alert = gquic_establish_record_layer_send_alert;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_establish_record_layer_read_handshake_msg_wrap(gquic_str_t *const ret, void *const self, gquic_coroutine_t *const co) {
    return gquic_handshake_establish_read_handshake_msg(ret, self, co);
}

static int gquic_establish_record_layer_set_rkey(void *const self,
                                                 const u_int8_t enc_level,
                                                 const gquic_tls_cipher_suite_t *const suite,
                                                 const gquic_str_t *const traffic_sec) {
    return gquic_handshake_establish_set_rkey(self, enc_level, suite, traffic_sec);
}

static int gquic_establish_record_layer_set_wkey(void *const self,
                                                 const u_int8_t enc_level,
                                                 const gquic_tls_cipher_suite_t *const suite,
                                                 const gquic_str_t *const traffic_sec) {
    return gquic_handshake_establish_set_wkey(self, enc_level, suite, traffic_sec);
}

static int gquic_establish_record_layer_write_record(size_t *const size, void *const self, const gquic_str_t *const data) {
    return gquic_handshake_establish_write_record(size, self, data);
}

static int gquic_establish_record_layer_send_alert(void *const self, const u_int8_t alert) {
    return gquic_handshake_establish_send_alert(self, alert);
}

static int gquic_establish_handle_post_handshake_msg(gquic_handshake_establish_t *const est, gquic_coroutine_t *const co) {
    gquic_establish_err_event_t *err_event = NULL;
    gquic_establish_ending_event_t *ending_event = NULL;
    void *done = NULL;
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_chain_recv(&done, co, 1, &est->done_chain, NULL);

    if (GQUIC_ASSERT(gquic_tls_conn_handle_post_handshake_msg(&est->conn, co))) {
        gquic_coroutine_chain_recv((void **) &ending_event, co, 1, &est->alert_chain, NULL);
        gquic_coroutine_chain_recv((void **) &err_event, co, 1, &est->err_chain, NULL);
        if (GQUIC_ASSERT(GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, ending_event->payload.alert_code, err_event->ret))) {
            goto finished;
        }
    }

finished:
    if (err_event != NULL) {
        gquic_list_release(err_event);
    }
    if (ending_event != NULL) {
        gquic_list_release(ending_event);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_establish_try_send_sess_ticket(gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t ticket = { 0, NULL };
    if (est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_get_sess_ticket(&ticket, &est->conn))) {
        gquic_str_reset(&ticket);
        GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, GQUIC_TLS_ALERT_INTERNAL_ERROR, exception);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_STR_SIZE(&ticket) != 0) {
        gquic_writer_str_t writer = ticket;
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_IO_WRITE(&est->one_rtt_output, &writer))) {
            gquic_str_reset(&ticket);
            GQUIC_PROCESS_DONE(exception);
        }
    }

    gquic_str_reset(&ticket);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_handshake_establish_get_initial_opener(gquic_header_protector_t **const protector,
                                                 gquic_common_long_header_opener_t **const opener,
                                                 gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || opener == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->initial_opener.available) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_KEY_DROPPED);
    }
    else {
        GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_opener_get_header_opener(protector, &est->initial_opener));
    }
    *opener = &est->initial_opener;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_get_handshake_opener(gquic_header_protector_t **const protector,
                                                   gquic_common_long_header_opener_t **const opener,
                                                   gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || opener == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->handshake_opener.available) {
        if (est->initial_opener.available) {
            sem_post(&est->mtx);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_UNAVAILABLE);
        }
        sem_post(&est->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_DROPPED);
    }
    else {
        GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_opener_get_header_opener(protector, &est->handshake_opener));
    }
    *opener = &est->handshake_opener;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_get_1rtt_opener(gquic_header_protector_t **const protector,
                                              gquic_auto_update_aead_t **const opener,
                                              gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || opener == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->has_1rtt_opener) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_KEY_UNAVAILABLE);
    }
    else {
        *protector = &est->aead.header_dec;
    }
    *opener = &est->aead;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_get_initial_sealer(gquic_header_protector_t **const protector,
                                                 gquic_common_long_header_sealer_t **const sealer,
                                                 gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || sealer == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->initial_sealer.available) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_KEY_DROPPED);
    }
    else {
        GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_sealer_get_header_sealer(protector, &est->initial_sealer));
    }
    *sealer = &est->initial_sealer;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_get_handshake_sealer(gquic_header_protector_t **const protector,
                                                   gquic_common_long_header_sealer_t **const sealer,
                                                   gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || sealer == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->handshake_sealer.available) {
        if (est->initial_sealer.available) {
            sem_post(&est->mtx);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_UNAVAILABLE);
        }
        sem_post(&est->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_KEY_DROPPED);
    }
    else {
        GQUIC_ASSERT_CAUSE(exception, gquic_common_long_header_sealer_get_header_sealer(protector, &est->handshake_sealer));
    }
    *sealer = &est->handshake_sealer;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_handshake_establish_get_1rtt_sealer(gquic_header_protector_t **const protector,
                                              gquic_auto_update_aead_t **const sealer,
                                              gquic_handshake_establish_t *const est) {
    int exception = GQUIC_SUCCESS;
    if (protector == NULL || sealer == NULL || est == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&est->mtx);
    if (!est->has_1rtt_sealer) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_KEY_UNAVAILABLE);
    }
    else {
        *protector = &est->aead.header_enc;
    }
    *sealer = &est->aead;
    sem_post(&est->mtx);

    GQUIC_PROCESS_DONE(exception);
}


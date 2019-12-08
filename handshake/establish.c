#include "handshake/establish.h"
#include "handshake/initial_aead.h"
#include "tls/alert.h"
#include <pthread.h>


static void *__establish_run(void *);
static int gquic_establish_check_enc_level(const u_int8_t, const u_int8_t);
static int gquic_establish_waiting_handshake_done_cmp(const void *const, const void *const);
static int gquic_establish_cli_handle_msg(gquic_handshake_establish_t *const, const u_int8_t);
static int gquic_establish_waiting_cli_handle_cmp(const void *const, const void *const);
static int gquic_establish_ser_handle_msg(gquic_handshake_establish_t *const, const u_int8_t);
static int gquic_establish_waiting_ser_handle_cmp(const void *const, const void *const);
static int gquic_establish_drop_initial_keys_wrap(void *const);

static int gquic_establish_record_layer_read_handshake_msg_wrap(gquic_str_t *const, void *const);
static int gquic_establish_record_layer_set_rkey(void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
static int gquic_establish_record_layer_set_wkey(void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
static int gquic_establish_record_layer_write_record(size_t *const, void *const, const gquic_str_t *const);
static int gquic_establish_record_layer_send_alert(void *const, const u_int8_t);

int gquic_handshake_event_init(gquic_handshake_event_t *const event) {
    if (event == NULL) {
        return -1;
    }
    event->self = NULL;
    event->on_recv_params = NULL;
    event->on_err = NULL;
    event->drop_keys = NULL;
    event->on_handshake_complete = NULL;

    return 0;
}

int gquic_handshake_establish_init(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        return -1;
    }

    est->cfg = NULL;
    gquic_tls_conn_init(&est->conn);
    gquic_handshake_event_init(&est->events);
    gquic_sem_list_init(&est->handshake_ending_events_queue);
    gquic_sem_list_init(&est->err_events_queue);
    gquic_sem_list_init(&est->msg_events_queue);
    gquic_sem_list_init(&est->handshake_process_events_queue);
    est->cli_hello_written = 0;
    est->is_client = 0;
    sem_init(&est->client_written_sem, 0, 0);
    sem_init(&est->mtx, 0, 1);
    est->read_enc_level = GQUIC_ENC_LV_INITIAL;
    est->write_enc_level = GQUIC_ENC_LV_INITIAL;
    gquic_io_init(&est->init_output);
    gquic_handshake_opener_init(&est->init_opener);
    gquic_handshake_sealer_init(&est->init_sealer);
    gquic_io_init(&est->handshake_output);
    gquic_handshake_opener_init(&est->handshake_opener);
    gquic_handshake_sealer_init(&est->handshake_sealer);
    gquic_io_init(&est->one_rtt_output);
    gquic_auto_update_aead_init(&est->aead);
    est->has_1rtt_sealer = 0;
    est->has_1rtt_opener = 0;

    gquic_handshake_extension_handler_init(&est->extension_handler);

    return 0;
}

int gquic_handshake_establish_release(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        return -1;
    }
    
    // TODO

    return 0;
}

int gquic_handshake_establish_assign(gquic_handshake_establish_t *const est,
                                     gquic_tls_config_t *const cfg,
                                     const gquic_str_t *const conn_id,
                                     const gquic_transport_parameters_t *const params,
                                     gquic_rtt_t *const rtt,
                                     const gquic_net_addr_t *const addr,
                                     const int is_client) {
    if (est == NULL || conn_id == NULL || params == NULL || cfg == NULL || rtt == NULL || addr == NULL) {
        return -1;
    }
    gquic_handshake_extension_handler_assign(&est->extension_handler, &est->handshake_process_events_queue, params, is_client);

    gquic_handshake_extension_handler_set_config_extension(cfg, &est->extension_handler);
    gquic_handshake_establish_set_record_layer(&cfg->alt_record, est);

    gquic_handshake_opener_release(&est->init_opener);
    gquic_handshake_sealer_release(&est->init_sealer);
    gquic_handshake_initial_aead_init(&est->init_sealer, &est->init_opener, conn_id, is_client);

    est->aead.rtt = rtt;
    est->cfg = cfg;
    est->is_client = is_client;

    gquic_tls_conn_assign(&est->conn, addr, cfg);
    return 0;
}

int gquic_handshake_establish_change_conn_id(gquic_handshake_establish_t *const est,
                                             const gquic_str_t *const conn_id) {
    if (est == NULL || conn_id == NULL) {
        return -1;
    }
    gquic_handshake_sealer_release(&est->handshake_sealer);
    gquic_handshake_opener_release(&est->handshake_opener);
    if (gquic_handshake_initial_aead_init(&est->handshake_sealer,
                                          &est->handshake_opener,
                                          conn_id,
                                          est->is_client) != 0) {
        return -2;
    }
    return 0;
}

int gquic_handshake_establish_1rtt_set_last_acked(gquic_handshake_establish_t *const est,
                                                  const u_int64_t pn) {
    if (est == NULL) {
        return -1;
    }
    est->aead.last_ack_pn = pn;
    if (est->handshake_opener.opener.aead.self != NULL) {
        gquic_handshake_opener_release(&est->handshake_opener);
        gquic_handshake_opener_init(&est->handshake_opener);
        gquic_handshake_sealer_release(&est->handshake_sealer);
        gquic_handshake_sealer_init(&est->handshake_sealer);
        GQUIC_HANDSHAKE_EVENT_DROP_KEYS(&est->events, GQUIC_ENC_LV_HANDSHAKE);
    }

    return 0;
}

int gquic_handshake_establish_run(gquic_handshake_establish_t *const est) {
    int ret = 0;
    gquic_establish_ending_event_t *ending_event = NULL;
    gquic_establish_err_event_t *err_event = NULL;
    gquic_establish_process_event_t *process_event = NULL;
    pthread_t run_thread;
    pthread_attr_t run_thread_attr;
    if (est == NULL) {
        return -1;
    }
    if (pthread_create(&run_thread, &run_thread_attr, __establish_run, est) != 0) {
        return -2;
    }
    if (gquic_sem_list_pop((void **) &ending_event, &est->handshake_ending_events_queue) != 0) {
        return -3;
    }
    switch (ending_event->type) {
    case GQUIC_ESTABLISH_ENDING_EVENT_ALERT:
        if (gquic_sem_list_pop((void **) &err_event, &est->err_events_queue) != 0) {
            ret = -4;
            goto failure;
        }
        if (GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, ending_event->payload.alert_code, err_event->ret) != 0) {
            ret = -5;
            goto failure;
        }
        break;

    case GQUIC_ESTABLISH_ENDING_EVENT_CLOSE:
        gquic_sem_list_close(&est->msg_events_queue);
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_handshake_done_cmp,
                                   NULL);
        break;

    case GQUIC_ESTABLISH_ENDING_EVENT_HANDSHAKE_COMPLETE:
        if (GQUIC_HANDSHAKE_EVENT_ON_HANDSHAKE_COMPLETE(&est->events) != 0) {
            ret = -6;
            goto failure;
        }
        if (!est->is_client) {
            // TODO send sess_ticket
        }
        break;
    }

    if (ending_event != NULL) {
        gquic_list_release(ending_event);
    }
    if (err_event != NULL) {
        gquic_list_release(err_event);
    }
    if (process_event != NULL) {
        gquic_list_release(process_event);
    }
    return 0;
failure:
    if (ending_event != NULL) {
        gquic_list_release(ending_event);
    }
    if (err_event != NULL) {
        gquic_list_release(err_event);
    }
    if (process_event != NULL) {
        gquic_list_release(process_event);
    }
    return ret;
}

static void *__establish_run(void *arg) {
    int err_ret;
    gquic_establish_ending_event_t *ending_event = NULL;
    gquic_establish_err_event_t *err_event = NULL;
    gquic_establish_process_event_t *process_event = NULL;
    gquic_handshake_establish_t *const est = arg;
    if (est == NULL) {
        goto finish;
    }
    if ((err_ret = gquic_tls_conn_handshake(&est->conn)) != 0) {
        if ((err_event = gquic_list_alloc(sizeof(gquic_establish_err_event_t))) == NULL) {
            goto finish;
        }
        err_event->ret = err_ret;
        gquic_sem_list_push(&est->err_events_queue, err_event);
        goto finish;
    }
    if ((ending_event = gquic_list_alloc(sizeof(gquic_establish_ending_event_t))) == NULL) {
        goto finish;
    }
    ending_event->type = GQUIC_ESTABLISH_ENDING_EVENT_HANDSHAKE_COMPLETE;
    gquic_sem_list_push(&est->handshake_ending_events_queue, ending_event);
finish:
    if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
        return NULL;
    }
    process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_DONE;
    gquic_sem_list_rpush(&est->handshake_process_events_queue, process_event);
    return NULL;
}

int gquic_handshake_establish_close(gquic_handshake_establish_t *const est) {
    gquic_establish_ending_event_t *event = NULL;
    gquic_establish_process_event_t *process_event = NULL;
    if (est == NULL) {
        return -1;
    }
    if ((event = gquic_list_alloc(sizeof(gquic_establish_ending_event_t))) == NULL) {
        return -2;
    }
    event->type = GQUIC_ESTABLISH_ENDING_EVENT_CLOSE;
    gquic_sem_list_push(&est->handshake_ending_events_queue, event);
    gquic_sem_list_waiting_pop((void **) &process_event,
                               &est->handshake_process_events_queue,
                               gquic_establish_waiting_handshake_done_cmp,
                               NULL);
    gquic_list_release(process_event);
    return 0;
}

int gquic_handshake_establish_handle_msg(gquic_handshake_establish_t *const est, const gquic_str_t *const data, const u_int8_t enc_level) {
    int ret = 0;
    u_int8_t type = 0;
    gquic_str_t *msg = NULL;
    if (est == NULL || data == NULL) {
        return -1;
    }
    type = GQUIC_STR_FIRST_BYTE(data);
    if ((ret = gquic_establish_check_enc_level(type, enc_level)) != 0) {
        if (GQUIC_HANDSHAKE_EVENT_ON_ERR(&est->events, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE, ret) != 0) {
            ret = -2;
        }
        return -3;
    }
    if ((msg = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
        return -4;
    }
    if (gquic_str_copy(msg, data) != 0) {
        return -5;
    }
    gquic_sem_list_push(&est->msg_events_queue, msg);
    if (enc_level == GQUIC_ENC_LV_1RTT) {
        // TODO new ticket OR key update
    }

    if (est->is_client) {
        ret = gquic_establish_cli_handle_msg(est, type);
    }
    else {
        ret = gquic_establish_ser_handle_msg(est, type);
    }
    if (ret < 0) {
        return -6;
    }
    return ret;
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
        return -1;
    }
    if (expect != enc_level) {
        return -2;
    }
    return 0;
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

static int gquic_establish_cli_handle_msg(gquic_handshake_establish_t *const est, const u_int8_t msg_type) {
    u_int8_t type;
    gquic_establish_process_event_t *process_event = NULL;
    if (est == NULL) {
        return -1;
    }
    switch (msg_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_cli_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
        case GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD:
            return 0;
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY:
            break;
        default:
            return -2;
        }
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_cli_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY:
            break;
        default:
            return -3;
        }
        return 1;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_cli_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_PARAM:
            GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(&est->events, &process_event->param);
            gquic_str_reset(&process_event->param);
            break;
        default:
            gquic_list_release(process_event);
            return -4;
        }
        gquic_list_release(process_event);
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_cli_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        default:
            return -1;
        }
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_cli_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        default:
            return -1;
        }
        return 1;
    }
    return 0;
}

static int gquic_establish_waiting_cli_handle_cmp(const void *const event, const void *const type) {
    const gquic_establish_process_event_t *process_event = event;
    if (event == NULL || type == NULL) {
        return -1;
    }
    switch (*(u_int8_t *) type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        if (process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_DONE) {
            return 0;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        if (process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_PARAM
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_DONE) {
            return 0;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        if (process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY
            || process_event->type == GQUIC_ESTABLISH_PROCESS_EVENT_DONE) {
            return 0;
        }
        break;
    }

    return 1;
}

static int gquic_establish_ser_handle_msg(gquic_handshake_establish_t *const est, const u_int8_t msg_type) {
    u_int8_t type;
    gquic_establish_process_event_t *process_event = NULL;
    if (est == NULL) {
        return -1;
    }
    switch (msg_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_ser_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            gquic_list_release(process_event);
            return 0;
        case GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD:
            gquic_list_release(process_event);
            return 0;
        case GQUIC_ESTABLISH_PROCESS_EVENT_PARAM:
            GQUIC_HANDSHAKE_EVENT_ON_RECV_PARAMS(&est->events, &process_event->param);
            gquic_str_reset(&process_event->param);
            gquic_list_release(process_event);
            break;
        default:
            gquic_list_release(process_event);
            return -2;
        }

        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_ser_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        default:
            return -1;
        }

        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_ser_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        default:
            return -1;
        }

        return 1;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        return 0;

    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        gquic_sem_list_waiting_pop((void **) &process_event,
                                   &est->handshake_process_events_queue,
                                   gquic_establish_waiting_ser_handle_cmp,
                                   &msg_type);
        type = process_event->type;
        gquic_list_release(process_event);
        switch (type) {
        case GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY:
            break;
        case GQUIC_ESTABLISH_PROCESS_EVENT_DONE:
            return 0;
        default:
            return -1;
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

int gquic_handshake_establish_read_handshake_msg(gquic_str_t *const msg, gquic_handshake_establish_t *const est) {
    gquic_str_t *tmp = NULL;
    if (msg == NULL || est == NULL) {
        return -1;
    }
    if (gquic_sem_list_pop((void **) &tmp, &est->msg_events_queue) != 0) {
        return -2;
    }
    msg->size = tmp->size;
    msg->val = tmp->val;
    gquic_list_release(tmp);
    return 0;
}

int gquic_handshake_establish_set_rkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec) {
    int ret = 0;
    gquic_establish_process_event_t *process_event = NULL;
    if (est == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    sem_wait(&est->mtx);
    switch (enc_level) {
    case GQUIC_ENC_LV_HANDSHAKE:
        est->read_enc_level = GQUIC_ENC_LV_HANDSHAKE;
        gquic_handshake_opener_release(&est->handshake_opener);
        gquic_handshake_opener_init(&est->handshake_opener);
        if (gquic_tls_create_aead(&est->handshake_opener.opener.aead, suite, traffic_sec) != 0) {
            ret = -2;
            goto failure;
        }
        if (gquic_header_protector_assign(&est->handshake_opener.opener.protector, suite, traffic_sec, 1) != 0) {
            ret = -3;
            goto failure;
        }
        est->handshake_opener.is_client = est->is_client;
        est->handshake_opener.drop_keys_self = est;
        est->handshake_opener.drop_keys = gquic_establish_drop_initial_keys_wrap;
        break;

    case GQUIC_ENC_LV_APP:
        est->read_enc_level = GQUIC_ENC_LV_1RTT;
        if (gquic_auto_update_aead_set_rkey(&est->aead, suite, traffic_sec) != 0) {
            ret = -4;
            goto failure;
        }
        est->has_1rtt_opener = 1;
        break;

    default:
        sem_post(&est->mtx);
        return -5;
    }
    sem_post(&est->mtx);
    if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
        return -6;
    }
    process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_RECV_RKEY;
    gquic_sem_list_push(&est->handshake_process_events_queue, process_event);
    return 0;
failure:
    sem_post(&est->mtx);
    return ret;
}

int gquic_handshake_establish_set_wkey(gquic_handshake_establish_t *const est,
                                       const u_int8_t enc_level,
                                       const gquic_tls_cipher_suite_t *const suite,
                                       const gquic_str_t *const traffic_sec) {
    int ret = 0;
    gquic_establish_process_event_t *process_event = NULL;
    if (est == NULL || suite == NULL || traffic_sec == NULL) {
        return -1;
    }
    sem_wait(&est->mtx);
    switch (enc_level) {
    case GQUIC_ENC_LV_HANDSHAKE:
        est->write_enc_level = GQUIC_ENC_LV_HANDSHAKE;
        gquic_handshake_sealer_release(&est->handshake_sealer);
        gquic_handshake_sealer_init(&est->handshake_sealer);
        if (gquic_tls_create_aead(&est->handshake_sealer.sealer.aead, suite, traffic_sec) != 0) {
            ret = -2;
            goto failure;
        }
        if (gquic_header_protector_assign(&est->handshake_sealer.sealer.protector, suite, traffic_sec, 1) != 0) {
            ret = -3;
            goto failure;
        }
        est->handshake_sealer.is_client = est->is_client;
        est->handshake_sealer.drop_keys_self = est;
        est->handshake_sealer.drop_keys = gquic_establish_drop_initial_keys_wrap;
        break;

    case GQUIC_ENC_LV_APP:
        est->write_enc_level = GQUIC_ENC_LV_1RTT;
        if (gquic_auto_update_aead_set_wkey(&est->aead, suite, traffic_sec) != 0) {
            ret = -4;
            goto failure;
        }
        est->has_1rtt_sealer = 1;
        break;

    default:
        sem_post(&est->mtx);
        return -5;
    }
    sem_post(&est->mtx);
    if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
        return -6;
    }
    process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_RECV_WKEY;
    gquic_sem_list_push(&est->handshake_process_events_queue, process_event);
    return 0;
failure:
    sem_post(&est->mtx);
    return ret;
}

int gquic_handshake_establish_drop_initial_keys(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        return -1;
    }
    sem_wait(&est->mtx);
    gquic_handshake_opener_release(&est->handshake_opener);
    gquic_handshake_sealer_release(&est->handshake_sealer);
    sem_post(&est->mtx);
    GQUIC_HANDSHAKE_EVENT_DROP_KEYS(&est->events, GQUIC_ENC_LV_INITIAL);
    return 0;
}

static int gquic_establish_drop_initial_keys_wrap(void *const est) {
    return gquic_handshake_establish_drop_initial_keys(est);
}

int gquic_handshake_establish_write_record(size_t *const size, gquic_handshake_establish_t *const est, const gquic_str_t *const data) {
    int ret = 0;
    gquic_establish_process_event_t *process_event = NULL;
    if (size == NULL || est == NULL || data == NULL) {
        return -1;
    }
    sem_wait(&est->mtx);
    switch (est->write_enc_level) {
    case GQUIC_ENC_LV_INITIAL:
        if (GQUIC_IO_WRITE(size, &est->init_output, data) != 0) {
            ret = -2;
            goto failure;
        }
        if (!est->cli_hello_written && est->is_client) {
            est->cli_hello_written = 1;
            sem_post(&est->client_written_sem);
        }
        else {
            if ((process_event = gquic_list_alloc(sizeof(gquic_establish_process_event_t))) == NULL) {
                ret = -3;
                goto failure;
            }
            process_event->type = GQUIC_ESTABLISH_PROCESS_EVENT_WRITE_RECORD;
            gquic_sem_list_push(&est->handshake_process_events_queue, process_event);
        }
        break;
    case GQUIC_ENC_LV_HANDSHAKE:
        if (GQUIC_IO_WRITE(size, &est->handshake_output, data) != 0) {
            ret = -4;
            goto failure;
        }
        break;
    default:
        sem_post(&est->mtx);
        return -5;
    }
    sem_post(&est->mtx);
    return 0;
failure:
    sem_post(&est->mtx);
    return ret;
}

int gquic_handshake_establish_send_alert(gquic_handshake_establish_t *const est, const u_int8_t alert) {
    gquic_establish_ending_event_t *ending_event = NULL;
    if (est == NULL) {
        return -1;
    }
    if ((ending_event = gquic_list_alloc(sizeof(gquic_establish_ending_event_t))) == NULL) {
        return -2;
    }
    ending_event->type = GQUIC_ESTABLISH_ENDING_EVENT_ALERT;
    ending_event->payload.alert_code = alert;
    gquic_sem_list_push(&est->handshake_ending_events_queue, ending_event);
    return 0;
}

int gquic_handshake_establish_set_record_layer(gquic_tls_record_layer_t *const record_layer, gquic_handshake_establish_t *const est) {
    if (record_layer == NULL || est == NULL) {
        return -1;
    }
    record_layer->self = est;
    record_layer->read_handshake_msg = gquic_establish_record_layer_read_handshake_msg_wrap;
    record_layer->set_rkey = gquic_establish_record_layer_set_rkey;
    record_layer->set_wkey = gquic_establish_record_layer_set_wkey;
    record_layer->write_record = gquic_establish_record_layer_write_record;
    record_layer->send_alert = gquic_establish_record_layer_send_alert;

    return 0;
}

static int gquic_establish_record_layer_read_handshake_msg_wrap(gquic_str_t *const ret, void *const self) {
    return gquic_handshake_establish_read_handshake_msg(ret, self);
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

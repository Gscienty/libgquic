#include "tls/handshake_server.h"
#include "tls/alert.h"
#include "tls/key_schedule.h"
#include "tls/server_hello_msg.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/auth.h"
#include "tls/cert_msg.h"
#include "tls/cert_req_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/finished_msg.h"
#include "tls/ticket.h"
#include "tls/meta.h"
#include "log.h"
#include "exception.h"
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

static u_int16_t __supported_sign_algos[] = {
    GQUIC_SIGALG_ED25519,
    GQUIC_SIGALG_PSS_SHA256,
    GQUIC_SIGALG_ECDSA_P256_SHA256,
    GQUIC_SIGALG_PSS_SHA384,
    GQUIC_SIGALG_PSS_SHA512,
    GQUIC_SIGALG_PKCS1_SHA256,
    GQUIC_SIGALG_PKCS1_SHA384,
    GQUIC_SIGALG_PKCS1_SHA512,
    GQUIC_SIGALG_ECDSA_P384_SHA384,
    GQUIC_SIGALG_ECDSA_P512_SHA512,
    GQUIC_SIGALG_PKCS1_SHA1,
    GQUIC_SIGALG_ECDSA_SHA1
};

static int gquic_tls_handshake_server_state_process_cli_hello(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_do_hello_retry_req(gquic_tls_handshake_server_state_t *const, const u_int16_t);
static int gquic_tls_handshake_server_state_send_dummy_change_cipher_spec(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_check_for_resumption(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_pick_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_params(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_finished(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_read_cli_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_read_cli_finished(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_illegal_client_hello_change(gquic_tls_client_hello_msg_t *const, gquic_tls_client_hello_msg_t *const);
static int gquic_tls_handshake_server_state_send_session_tickets(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_should_send_session_tickets(gquic_tls_handshake_server_state_t *const);

static int mutual_protocol(const gquic_str_t **const, const gquic_list_t *const, const gquic_list_t *const);
static int gquic_tls_handshake_server_state_request_cli_cert(gquic_tls_handshake_server_state_t *const);

static u_int16_t __cipher_suites[] = {
    GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384
};

int gquic_tls_handshake_server_state_init(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    ser_state->conn = NULL;
    ser_state->c_hello = NULL;
    ser_state->s_hello = NULL;
    ser_state->sent_dummy_ccs = 0;
    ser_state->using_psk = 0;
    ser_state->suite = NULL;
    ser_state->cert = NULL;
    ser_state->sigalg = 0;
    gquic_str_init(&ser_state->early_sec);
    gquic_str_init(&ser_state->shared_key);
    gquic_str_init(&ser_state->handshake_sec);
    gquic_str_init(&ser_state->master_sec);
    gquic_str_init(&ser_state->traffic_sec);
    gquic_tls_mac_init(&ser_state->transport);
    gquic_str_init(&ser_state->cli_finished);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_handshake_server_state_release(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (ser_state->c_hello != NULL) {
        gquic_tls_msg_release(ser_state->c_hello);
    }
    if (ser_state->s_hello != NULL) {
        gquic_tls_msg_release(ser_state->s_hello);
    }
    PKCS12_free(ser_state->cert);
    gquic_str_reset(&ser_state->early_sec);
    gquic_str_reset(&ser_state->shared_key);
    gquic_str_reset(&ser_state->handshake_sec);
    gquic_str_reset(&ser_state->master_sec);
    gquic_str_reset(&ser_state->traffic_sec);
    gquic_tls_mac_dtor(&ser_state->transport);
    gquic_str_reset(&ser_state->cli_finished);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_server_handshake(gquic_tls_conn_t *const conn) {
    int exception = GQUIC_SUCCESS;
    gquic_tls_handshake_server_state_t ser_state;
    if (conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_handshake_server_state_init(&ser_state);
    ser_state.conn = conn;
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_set_alt_record(conn));

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server inited handshake_server_state");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake((void **) &ser_state.c_hello, conn))
        || GQUIC_TLS_MSG_META(ser_state.c_hello).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        gquic_tls_msg_release(ser_state.c_hello);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server received CHELLO record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_server_handshake_state_handshake(&ser_state))) {
        gquic_tls_handshake_server_state_release(&ser_state);
        GQUIC_PROCESS_DONE(exception);
    }
    
    gquic_tls_handshake_server_state_release(&ser_state);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_server_handshake_state_handshake(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server TLS handshake start");

    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_process_cli_hello(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_check_for_resumption(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_pick_cert(ser_state));
    ser_state->conn->buffering = 1;
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_send_ser_params(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_send_ser_cert(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_send_ser_finished(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_read_cli_cert(ser_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_server_state_read_cli_finished(ser_state));
    ser_state->conn->handshake_status = 1;

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server TLS handshake finished");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_handshake_server_state_process_cli_hello(gquic_tls_handshake_server_state_t *const ser_state) {
    size_t count;
    size_t i;
    int exception = GQUIC_SUCCESS;
    gquic_list_t default_cipher_suites;
    gquic_list_t curve_perfers;
    gquic_tls_ecdhe_params_t ecdhe_param;
    u_int16_t selected_group = 0;
    u_int16_t *suite_id = NULL;
    gquic_tls_key_share_t *cli_key_share = NULL;
    gquic_tls_key_share_t *ks = NULL;
    u_int16_t *group = NULL;
    u_int16_t *perfer_group = NULL;
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server process CHELLO record");
    gquic_list_head_init(&default_cipher_suites);
    gquic_list_head_init(&curve_perfers);
    gquic_tls_ecdhe_params_init(&ecdhe_param);

    count = sizeof(__cipher_suites) / sizeof(u_int16_t);
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &cipher_suite, sizeof(u_int16_t)))) {
            goto failure;
        }
        *cipher_suite = __cipher_suites[i];
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&default_cipher_suites, cipher_suite))) {
            goto failure;
        }
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_server_hello_msg_alloc(&ser_state->s_hello))) {
        goto failure;
    }
    GQUIC_TLS_MSG_INIT(ser_state->s_hello);
    ser_state->s_hello->vers = GQUIC_TLS_VERSION_13;
    ser_state->s_hello->supported_version = ser_state->c_hello->vers;

    if (gquic_list_head_empty(&ser_state->c_hello->supported_versions)) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_UNSUPPORT_VERSIONS);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->c_hello->compression_methods) != 1
        || GQUIC_STR_FIRST_BYTE(&ser_state->c_hello->compression_methods) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&ser_state->s_hello->random, 32))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (RAND_bytes(GQUIC_STR_VAL(&ser_state->s_hello->random), 32) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RANDOM_FAILED);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->c_hello->secure_regegotation) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_HANDSHAKE_FAILED);
        goto failure;
    }
    if (ser_state->c_hello->early_data) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_UNSUPPORT_EXTENSION);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&ser_state->s_hello->sess_id, &ser_state->c_hello->sess_id))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    ser_state->s_hello->compression_method = 0;
    GQUIC_LIST_FOREACH(suite_id, (ser_state->conn->cfg->ser_perfer_cipher_suite ? &default_cipher_suites : &ser_state->c_hello->cipher_suites)) {
        gquic_list_t *supported = ser_state->conn->cfg->ser_perfer_cipher_suite ? &ser_state->c_hello->cipher_suites : &default_cipher_suites;
        if (!GQUIC_ASSERT(gquic_tls_choose_cipher_suite(&ser_state->suite, supported, *suite_id))) {
            break;
        }
    }
    if (ser_state->suite == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_HANDSHAKE_FAILED);
        goto failure;
    }
    ser_state->conn->cipher_suite = ser_state->suite->id;
    ser_state->s_hello->cipher_suite = ser_state->suite->id;
    if (GQUIC_ASSERT_CAUSE(exception, ser_state->suite->mac(&ser_state->transport, GQUIC_TLS_VERSION_13, NULL))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_config_curve_preferences(&curve_perfers))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    GQUIC_LIST_FOREACH(perfer_group, &curve_perfers) {
        GQUIC_LIST_FOREACH(ks, &ser_state->c_hello->key_shares) {
            if (ks->group == *perfer_group) {
                selected_group = *perfer_group;
                cli_key_share = ks;
                goto select_curve_perfers;
            }
        }
        if (selected_group == 0) {
            continue;
        }
        GQUIC_LIST_FOREACH(group, &ser_state->c_hello->supported_curves) {
            if (*group == *perfer_group) {
                selected_group = *group;
                break;
            }
        }
    }
select_curve_perfers:
    if (selected_group == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_HANDSHAKE_FAILED);
        goto failure;
    }
    if (cli_key_share == NULL) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_handshake_server_state_do_hello_retry_req(ser_state, selected_group))) {
            goto failure;
        }
        cli_key_share = GQUIC_LIST_FIRST(&ser_state->c_hello->key_shares);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_generate(&ecdhe_param, selected_group))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    ser_state->s_hello->ser_share.group = selected_group;
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_param, &ser_state->s_hello->ser_share.data))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_param, &ser_state->shared_key, &cli_key_share->data))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->shared_key) == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&ser_state->conn->ser_name, &ser_state->c_hello->ser_name))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server generated SHELLO record");

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server process CHELLO extensions");
    if (ser_state->conn->cfg->received_extensions != NULL
        && GQUIC_ASSERT_CAUSE(exception,
                              ser_state->conn->cfg->received_extensions(ser_state->conn->cfg->ext_self,
                                                                        GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO,
                                                                        &ser_state->c_hello->extensions))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    while (!gquic_list_head_empty(&default_cipher_suites)) {
        gquic_list_release(GQUIC_LIST_FIRST(&default_cipher_suites));
    }
    while (!gquic_list_head_empty(&curve_perfers)) {
        gquic_list_release(GQUIC_LIST_FIRST(&curve_perfers));
    }
    gquic_tls_ecdhe_params_dtor(&ecdhe_param);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    while (!gquic_list_head_empty(&default_cipher_suites)) {
        gquic_list_release(GQUIC_LIST_FIRST(&default_cipher_suites));
    }
    while (!gquic_list_head_empty(&curve_perfers)) {
        gquic_list_release(GQUIC_LIST_FIRST(&curve_perfers));
    }
    gquic_tls_ecdhe_params_dtor(&ecdhe_param);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_do_hello_retry_req(gquic_tls_handshake_server_state_t *const ser_state, const u_int16_t selected_group) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t c_hash = { 0, NULL };
    gquic_tls_server_hello_msg_t *hello_retry_req = NULL;
    gquic_tls_client_hello_msg_t *c_hello = NULL;
    size_t _;
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_hello_msg_alloc(&hello_retry_req));
    GQUIC_TLS_MSG_INIT(hello_retry_req);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, ser_state->c_hello))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_sum(&c_hash, &ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_reset(&ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    const u_int8_t hash_cnt[] = { GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH, 0, 0, (u_int8_t) GQUIC_STR_SIZE(&c_hash) };
    const gquic_str_t hash = { sizeof(hash_cnt), (void *) hash_cnt };
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &hash))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &c_hash))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    hello_retry_req->vers = ser_state->s_hello->vers;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&hello_retry_req->random, gquic_tls_hello_retry_request_random()))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&hello_retry_req->sess_id, &ser_state->s_hello->sess_id))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    hello_retry_req->cipher_suite = ser_state->s_hello->cipher_suite;
    hello_retry_req->compression_method = ser_state->s_hello->compression_method;
    hello_retry_req->supported_version = ser_state->s_hello->supported_version;
    hello_retry_req->selected_group = ser_state->s_hello->selected_group;

    gquic_str_reset(&buf);

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, hello_retry_req))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_handshake_server_state_send_dummy_change_cipher_spec(ser_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake((void **) &c_hello, ser_state->conn))
        || GQUIC_TLS_MSG_META(c_hello).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        gquic_tls_msg_release(c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        goto failure;
    }
    if ((!gquic_list_head_empty(&c_hello->key_shares)
         && GQUIC_LIST_FIRST(&c_hello->key_shares) == gquic_list_prev(GQUIC_LIST_PAYLOAD(&c_hello->key_shares)))
        || ((gquic_tls_key_share_t *) GQUIC_LIST_FIRST(&c_hello->key_shares))->group != selected_group) {
        gquic_tls_msg_release(c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (c_hello->early_data) {
        gquic_tls_msg_release(c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }

    if (gquic_tls_handshake_server_state_illegal_client_hello_change(c_hello, ser_state->c_hello)) {
        gquic_tls_msg_release(c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    gquic_tls_msg_release(ser_state->c_hello);
    ser_state->c_hello = c_hello;

    gquic_str_reset(&buf);
    gquic_str_reset(&c_hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:

    gquic_str_reset(&buf);
    gquic_str_reset(&c_hash);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_illegal_client_hello_change(gquic_tls_client_hello_msg_t *const c_hello1,
                                                                        gquic_tls_client_hello_msg_t *const c_hello2) {
    if (c_hello1 == NULL || c_hello2 == NULL) {
        return 1;
    }

    // TODO

    return 0;
}

static int gquic_tls_handshake_server_state_send_dummy_change_cipher_spec(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (ser_state->sent_dummy_ccs) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    ser_state->sent_dummy_ccs = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_handshake_server_state_check_for_resumption(gquic_tls_handshake_server_state_t *const ser_state) {
    int mode = 0;
    size_t i;
    int psk_identities_count = 0;
    int psk_binders_count = 0;
    void *_ = NULL;
    gquic_tls_psk_identity_t *identity = NULL;
    gquic_str_t plain_text = { 0, NULL };
    gquic_tls_sess_state_t sess_state;
    const gquic_tls_cipher_suite_t *psk_suite = NULL;
    int sess_has_client_certs = 0;
    int need_client_certs = 0;
    int exception = GQUIC_SUCCESS;
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_sess_state_init(&sess_state);
    if (ser_state->conn->cfg->sess_ticket_disabled) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    
    for (i = 0; i < GQUIC_STR_SIZE(&ser_state->c_hello->psk_modes); i++) {
        if (((u_int8_t *) GQUIC_STR_VAL(&ser_state->c_hello->psk_modes))[i] == 1) {
            mode = 1;
            break;
        }
    }
    if (!mode) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_LIST_FOREACH(_, &ser_state->c_hello->psk_identities) {
        psk_identities_count++;
    }
    GQUIC_LIST_FOREACH(_, &ser_state->c_hello->psk_binders) {
        psk_binders_count++;
    }
    if (psk_binders_count != psk_identities_count) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (psk_identities_count == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    i = 0;
    GQUIC_LIST_FOREACH(identity, &ser_state->c_hello->psk_identities) {
        int ignore;
        if (i >= 5) {
            break;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_decrypt_ticket(&plain_text, &ignore, ser_state->conn, &identity->label))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            GQUIC_PROCESS_DONE(exception);
        }
        if (GQUIC_STR_SIZE(&plain_text) == 0) {
            goto continue_loop;
        }
        gquic_reader_str_t reader = plain_text;
        if (GQUIC_ASSERT(gquic_tls_sess_state_deserialize(&sess_state, &reader))) {
            goto continue_loop;
        }
        if (time(NULL) - sess_state.create_at < 7 * 24 * 60 * 60) {
            goto continue_loop;
        }
        if (GQUIC_ASSERT(gquic_tls_get_cipher_suite(&psk_suite, sess_state.cipher_suite))) {
            goto continue_loop;
        }
        if (psk_suite == NULL || psk_suite->hash != ser_state->suite->hash) {
            goto continue_loop;
        }
        sess_has_client_certs = !gquic_list_head_empty(&sess_state.cert.certs);
        need_client_certs = gquic_tls_requires_cli_cert(ser_state->conn->cfg->cli_auth);
        if (need_client_certs && !sess_has_client_certs) {
            goto continue_loop;
        }
        if (sess_has_client_certs && ser_state->conn->cfg->cli_auth == 0) {
            goto continue_loop;
        }

        exception = GQUIC_SUCCESS;
        gquic_str_t psk = { 0, NULL };
        gquic_str_t binder_key = { 0, NULL };
        gquic_str_t psk_binder = { 0, NULL };
        gquic_str_t buf = { 0, NULL };
        gquic_tls_mac_t transport;
        gquic_tls_mac_t hash;
        static const gquic_str_t label = { 10, "resumption" };
        static const gquic_str_t resumption_binder_label = { 10, "res binder" };
        gquic_tls_mac_init(&transport);
        gquic_tls_mac_init(&hash);

        ser_state->suite->mac(&hash, GQUIC_TLS_VERSION_13, NULL);
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_tls_cipher_suite_expand_label(&psk,
                                                                   ser_state->suite,
                                                                   &sess_state.resumption_sec, &label, NULL, EVP_MD_size(hash.md)))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cipher_suite_extract(&ser_state->early_sec, ser_state->suite, &psk, NULL))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_tls_cipher_suite_derive_secret(&binder_key,
                                                                    ser_state->suite,
                                                                    NULL, &ser_state->early_sec, &resumption_binder_label))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_copy(&transport, &ser_state->transport))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, ser_state->c_hello))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        buf.size = gquic_tls_client_hello_msg_size_without_binders(ser_state->c_hello);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cipher_suite_finished_hash(&psk_binder, ser_state->suite, &binder_key, &transport))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        size_t k = 0;
        gquic_str_t *psk_binder_inner = NULL;
        GQUIC_LIST_FOREACH(psk_binder_inner, &ser_state->c_hello->psk_binders) {
            if (k == i) {
                if (gquic_str_cmp(psk_binder_inner, &psk_binder) != 0) {
                    gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
                    GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
                    goto failure;
                }
                break;
            }
            k++;
        }

        // TODO process client certs
        
        ser_state->s_hello->selected_identity_persent = 1;
        ser_state->s_hello->selected_identity = i;
        ser_state->using_psk = 1;
        ser_state->conn->did_resume = 1;

        gquic_str_reset(&plain_text);
        gquic_tls_sess_state_dtor(&sess_state);
        gquic_tls_sess_state_init(&sess_state);

        gquic_tls_mac_dtor(&hash);
        gquic_tls_mac_dtor(&transport);
        gquic_str_reset(&psk);
        gquic_str_reset(&binder_key);
        gquic_str_reset(&psk_binder);
        gquic_str_reset(&buf);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
        gquic_str_reset(&plain_text);
        gquic_tls_sess_state_dtor(&sess_state);
        gquic_tls_sess_state_init(&sess_state);

        gquic_tls_mac_dtor(&hash);
        gquic_tls_mac_dtor(&transport);
        gquic_str_reset(&psk);
        gquic_str_reset(&binder_key);
        gquic_str_reset(&psk_binder);
        gquic_str_reset(&buf);
        GQUIC_PROCESS_DONE(exception);

continue_loop:
        i++;
        gquic_str_reset(&plain_text);
        gquic_tls_sess_state_dtor(&sess_state);
        gquic_tls_sess_state_init(&sess_state);
        psk_suite = NULL;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_handshake_server_state_pick_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = GQUIC_SUCCESS;
    gquic_list_t supported_algs;
    u_int16_t *perfer_alg = NULL;
    if (ser_state == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (ser_state->using_psk) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server pick cert");

    gquic_list_head_init(&supported_algs);
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_CONFIG_GET_SER_CERT(&ser_state->cert, ser_state->conn->cfg, ser_state->c_hello))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_sig_schemes_from_cert(&supported_algs, ser_state->cert))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (gquic_list_head_empty(&supported_algs)) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_BAD_CERT);
        goto failure;
    }
    GQUIC_LIST_FOREACH(perfer_alg, &ser_state->c_hello->supported_sign_algos) {
        if (gquic_tls_is_supported_sigalg(*perfer_alg, &supported_algs)) {
            ser_state->sigalg = *perfer_alg;
            break;
        }
    }
    if (ser_state->sigalg == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_HANDSHAKE_FAILED);
        goto failure;
    }
    
    while (!gquic_list_head_empty(&supported_algs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_algs));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    while (!gquic_list_head_empty(&supported_algs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_algs));
    }
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_send_ser_params(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t early_sec = { 0, NULL };
    gquic_str_t early_sec_derived_sec = { 0, NULL };
    gquic_str_t cli_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    gquic_tls_encrypt_ext_msg_t *enc_ext = NULL;
    static const gquic_str_t derived_label = { 7, "derived" };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
    size_t _;
    const gquic_str_t *selected_proto = NULL;
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_encrypt_ext_msg_alloc(&enc_ext))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server calc transport (CHELLO)");

    GQUIC_TLS_MSG_INIT(enc_ext);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, ser_state->c_hello))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    gquic_str_reset(&buf);

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server calc transport (SHELLO)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, ser_state->s_hello))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server send SHELLO record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->early_sec) == 0) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cipher_suite_extract(&early_sec, ser_state->suite, NULL, NULL))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
    }
    else {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&early_sec, &ser_state->early_sec))) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server generate early sec (GQUIC_ENC_LV_HANDSHAKE)");

    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, ser_state->suite, NULL, &early_sec, &derived_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_extract(&ser_state->handshake_sec,
                                                          ser_state->suite, &ser_state->shared_key, &early_sec_derived_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server set read key");
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&cli_sec,
                                                                ser_state->suite,
                                                                &ser_state->transport, &ser_state->handshake_sec, &cli_handshake_traffic_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&ser_state->conn->in, GQUIC_ENC_LV_HANDSHAKE, ser_state->suite, &cli_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->in, ser_state->suite, &cli_sec, 1))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                                                ser_state->suite,
                                                                &ser_state->transport, &ser_state->handshake_sec, &ser_handshake_traffic_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server set write key (GQUIC_ENC_LV_HANDSHAKE)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&ser_state->conn->out, GQUIC_ENC_LV_HANDSHAKE, ser_state->suite, &ser_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->out, ser_state->suite, &ser_sec, 0))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    

    if (!gquic_list_head_empty(&ser_state->c_hello->alpn_protos)) {
        if (mutual_protocol(&selected_proto, &ser_state->c_hello->alpn_protos, &ser_state->conn->cfg->next_protos) == 0) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&enc_ext->alpn_proto, selected_proto))) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                goto failure;
            }
            if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&ser_state->conn->cli_proto, selected_proto))) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                goto failure;
            }
        }
    }
    if (ser_state->conn->cfg->enforce_next_proto_selection && GQUIC_STR_SIZE(&ser_state->conn->cli_proto) == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_NO_APP_PROTOCOL);
        goto failure;
    }
    if (ser_state->conn->cfg->extensions != NULL
        && GQUIC_ASSERT_CAUSE(exception,
                              ser_state->conn->cfg->extensions(&enc_ext->addition_exts,
                                                               ser_state->conn->cfg->ext_self, GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    gquic_str_reset(&buf);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, enc_ext))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_tls_msg_release(&enc_ext);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&buf);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_tls_msg_release(&enc_ext);
    GQUIC_PROCESS_DONE(exception);
}

static int mutual_protocol(const gquic_str_t **const ret, const gquic_list_t *const protos, const gquic_list_t *const perfer_protos) {
    gquic_str_t *proto = NULL;
    if (protos == NULL || perfer_protos == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_t *perfer_proto = NULL;

    GQUIC_LIST_FOREACH(perfer_proto, perfer_protos) {
        GQUIC_LIST_FOREACH(proto, protos) {
            if (gquic_str_cmp(proto, perfer_proto) == 0) {
                *ret = perfer_proto;
                GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
            }
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
}

static int gquic_tls_handshake_server_state_send_ser_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = GQUIC_SUCCESS;
    gquic_tls_cert_req_msg_t *cert_req = NULL;
    gquic_tls_cert_msg_t *cert_msg = NULL;
    gquic_tls_cert_verify_msg_t *verify_msg = NULL;
    gquic_str_t buf = { 0, NULL };
    PKCS12 *cert_p12 = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 **cert = NULL;
    size_t _;
    static const gquic_str_t ser_sign_cnt = { 38, "GQUIC-TLSv1.3, server SignatureContent" };
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (ser_state->using_psk) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server send cert");

    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_req_msg_alloc(&cert_req));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_msg_alloc(&cert_msg));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_verify_msg_alloc(&verify_msg));
    GQUIC_TLS_MSG_INIT(cert_req);
    GQUIC_TLS_MSG_INIT(cert_msg);
    GQUIC_TLS_MSG_INIT(verify_msg);
    if (gquic_tls_handshake_server_state_request_cli_cert(ser_state)) {
        cert_req->ocsp_stapling = 1;
        cert_req->scts = 1;

        gquic_list_head_init(&cert_req->supported_sign_algo);
        size_t count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        size_t i;
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = NULL;
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &sigalg, sizeof(u_int16_t)))) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&cert_req->supported_sign_algo, sigalg))) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                goto failure;
            }
        }
    }
    if (ser_state->c_hello->scts) {
        // TODO
    }
    if (ser_state->c_hello->ocsp_stapling) {
        // TODO
    }
    if (PKCS12_parse(ser_state->cert, NULL, &pkey, &x509, NULL) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_BAD_CERT);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &cert, sizeof(X509 *)))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    *cert = x509;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&cert_msg->cert.certs, cert))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    // TODO add server appendix certs
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, cert_msg))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server calc transport (CERT)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server send CERT record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    gquic_str_reset(&buf);

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server use cert pkey calc verify (ref transport)");

    verify_msg->has_sign_algo = 1;
    verify_msg->sign_algo = ser_state->sigalg;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_signed_msg(&buf, NULL, &ser_sign_cnt, &ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (EVP_MD_CTX_init(md_ctx) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    if (EVP_DigestSign(md_ctx, NULL, &_, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&verify_msg->sign, _))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (EVP_DigestSign(md_ctx, GQUIC_STR_VAL(&verify_msg->sign), &_, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    gquic_str_reset(&buf);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, verify_msg))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server calc transport (VERIFY)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server send VERIFY record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_tls_msg_release(cert_req);
    gquic_tls_msg_release(cert_msg);
    gquic_tls_msg_release(verify_msg);
    gquic_str_reset(&buf);
    if (cert_p12 != NULL) {
        PKCS12_free(cert_p12);
    }
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:

    gquic_tls_msg_release(cert_req);
    gquic_tls_msg_release(cert_msg);
    gquic_tls_msg_release(verify_msg);
    gquic_str_reset(&buf);
    if (cert_p12 != NULL) {
        PKCS12_free(cert_p12);
    }
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_request_cli_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return 0;
    }
    return ser_state->conn->cfg->cli_auth >= GQUIC_CLI_AUTH_REQ && !ser_state->using_psk;
}

static int gquic_tls_handshake_server_state_send_ser_finished(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = GQUIC_SUCCESS;
    gquic_tls_finished_msg_t *finished = NULL;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t handshake_sec_derived_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    size_t _;
    static const gquic_str_t derived_label = { 7, "derived" };
    static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_finished_msg_alloc(&finished));
    GQUIC_TLS_MSG_INIT(finished);

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server set finished->verify (verify)");

    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_finished_hash(&finished->verify,
                                             ser_state->suite,
                                             &ser_state->conn->out.traffic_sec, &ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, finished))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server calc transport (FINISHED)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server send FINISHED record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&handshake_sec_derived_sec,
                                                                ser_state->suite, NULL, &ser_state->handshake_sec, &derived_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cipher_suite_extract(&ser_state->master_sec, ser_state->suite, NULL, &handshake_sec_derived_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_state->traffic_sec,
                                                                ser_state->suite,
                                                                &ser_state->transport, &ser_state->master_sec, &cli_handshake_traffic_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                                                ser_state->suite,
                                                                &ser_state->transport, &ser_state->master_sec, &ser_handshake_traffic_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server set write key (GQUIC_ENC_LV_APP)");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&ser_state->conn->out, GQUIC_ENC_LV_APP, ser_state->suite, &ser_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->out, ser_state->suite, &ser_sec, 0))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_export_keying_material(&ser_state->conn->ekm,
                                                                         ser_state->suite,
                                                                         &ser_state->master_sec, &ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (!gquic_tls_handshake_server_state_request_cli_cert(ser_state)) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_handshake_server_state_send_session_tickets(ser_state))) {
            goto failure;
        }
    }
    
    gquic_tls_msg_release(finished);
    gquic_str_reset(&buf);
    gquic_str_reset(&handshake_sec_derived_sec);
    gquic_str_reset(&ser_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_msg_release(finished);
    gquic_str_reset(&buf);
    gquic_str_reset(&handshake_sec_derived_sec);
    gquic_str_reset(&ser_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_read_cli_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    
    // TODO
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_handshake_server_state_read_cli_finished(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = GQUIC_SUCCESS;
    gquic_tls_finished_msg_t *finished = NULL;
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    
    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server waiting client FINISHED record");

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake((void **) &finished, ser_state->conn))
        || GQUIC_TLS_MSG_META(finished).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server received client FINISHED record");

    if (gquic_str_cmp(&ser_state->cli_finished, &finished->verify) != 0) {
        GQUIC_LOG(GQUIC_LOG_ERROR, "TLS server verify FINISHED failed");
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_half_conn_set_key(&ser_state->conn->in, GQUIC_ENC_LV_APP, ser_state->suite, &ser_state->traffic_sec))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "TLS server set read key (GQUIC_ENC_LV_APP)");

    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->in, ser_state->suite, &ser_state->traffic_sec, 1))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_tls_msg_release(finished);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_msg_release(finished);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_send_session_tickets(gquic_tls_handshake_server_state_t *const ser_state) {
    int exception = 0;
    gquic_tls_finished_msg_t *cli_finished = NULL;
    gquic_str_t buf = { 0, NULL };
    static const gquic_str_t resumption_label = { 5, "res master" };
    if (ser_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_finished_msg_alloc(&cli_finished));
    GQUIC_TLS_MSG_INIT(cli_finished);
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_finished_hash(&ser_state->cli_finished,
                                                                ser_state->suite,
                                                                &ser_state->conn->in.traffic_sec, &ser_state->transport))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&cli_finished->verify, &ser_state->cli_finished))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, cli_finished))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&ser_state->transport, &buf))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    if (!gquic_tls_handshake_server_state_should_send_session_tickets(ser_state)) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_state->conn->resumption_sec,
                                                                ser_state->suite,
                                                                &ser_state->transport, &ser_state->master_sec, &resumption_label))) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_tls_msg_release(cli_finished);
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_msg_release(cli_finished);
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_handshake_server_state_should_send_session_tickets(gquic_tls_handshake_server_state_t *const ser_state) {
    size_t i;
    if (ser_state == NULL) {
        return 0;
    }

    if (ser_state->conn->cfg->sess_ticket_disabled) {
        return 0;
    }
    for (i = 0; i < GQUIC_STR_SIZE(&ser_state->c_hello->psk_modes); i++) {
        if (((u_int8_t *) GQUIC_STR_VAL(&ser_state->c_hello->psk_modes))[i] == 1) {
            return 1;
        }
    }

    return 0;
}

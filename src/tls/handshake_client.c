#include "tls/handshake_client.h"
#include "tls/common.h"
#include "tls/key_schedule.h"
#include "tls/alert.h"
#include "tls/hello_req_msg.h"
#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/new_sess_ticket_msg.h"
#include "tls/new_sess_ticket_msg.h"
#include "tls/cert_msg.h"
#include "tls/cert_req_msg.h"
#include "tls/cert_status_msg.h"
#include "tls/server_key_exchange_msg.h"
#include "tls/server_hello_done_msg.h"
#include "tls/client_key_exchange_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/next_proto_msg.h"
#include "tls/finished_msg.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/end_of_early_data_msg.h"
#include "tls/key_update_msg.h"
#include "tls/prf.h"
#include "tls/auth.h"
#include "tls/meta.h"
#include "util/time.h"
#include "exception.h"
#include <openssl/tls1.h>
#include <openssl/rand.h>

static int gquic_proto_copy(void *, const void *);

static u_int16_t __cipher_suites[] = {
    GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384
};

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

static int gquic_tls_handshake_client_hello_edch_params_init(gquic_tls_ecdhe_params_t *const,
                                                             gquic_tls_client_hello_msg_t *const,
                                                             const gquic_tls_config_t *const);


static int gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_process_hello_retry_request(gquic_coroutine_t *const, gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_process_server_hello(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_establish_handshake_keys(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_params(gquic_coroutine_t *const, gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_cert(gquic_coroutine_t *const, gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_finished(gquic_coroutine_t *const, gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_cli_cert(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_cli_finished(gquic_tls_handshake_client_state_t *const);

static int mutual_protocol(const gquic_str_t *const, const gquic_list_t *const);

int gquic_tls_handshake_client_state_init(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cli_state->conn = NULL;
    cli_state->s_hello = NULL;
    cli_state->c_hello = NULL;
    gquic_str_init(&cli_state->early_sec);
    gquic_str_init(&cli_state->binder_key);
    cli_state->cert_req = NULL;
    cli_state->using_psk = 0;
    cli_state->sent_dummy_ccs = 0;
    cli_state->suite = NULL;
    gquic_tls_ecdhe_params_init(&cli_state->ecdhe_params);
    gquic_tls_mac_init(&cli_state->transport);
    gquic_str_init(&cli_state->master_sec);
    gquic_str_init(&cli_state->traffic_sec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t **const msg,
                                          gquic_tls_ecdhe_params_t *const params,
                                          const gquic_tls_conn_t *conn) {
    gquic_str_t *proto;
    size_t next_protos_len = 0;
    gquic_list_t supported_versions;
    int exception = GQUIC_SUCCESS;
    size_t count;
    size_t i;

    if (msg == NULL || params == NULL || conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&supported_versions);

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_hello_msg_alloc(msg))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_MSG_INIT(*msg))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_init(params))) {
        goto failure;
    }

    if (GQUIC_STR_SIZE(&conn->cfg->ser_name) == 0 && !conn->cfg->insecure_skiy_verify) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_VERIFY_SERVER_BUT_SERVER_NAME_EMPTY);
        goto failure;
    }
    GQUIC_LIST_FOREACH(proto, &conn->cfg->next_protos) {
        if (proto->size == 0 || proto->size > 255) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_PROTO_SIZE_UNEXCEPTED);
            goto failure;
        }
        next_protos_len += proto->size;
    }
    if (next_protos_len > 0xffff) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_PROTOS_TOO_LONG);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_config_supported_versions(&supported_versions, conn->cfg, 1))) {
        goto failure;
    }
    if (gquic_list_head_empty(&supported_versions)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_UNSUPPORT_VERSIONS);
        goto failure;
    }
    (*msg)->vers = *(u_int16_t *) GQUIC_LIST_FIRST(&supported_versions);

    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&(*msg)->compression_methods, 1))) {
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&(*msg)->compression_methods) = 0;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&(*msg)->random, 32))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&(*msg)->sess_id, 32))) {
        goto failure;
    }
    (*msg)->ocsp_stapling = 1;
    (*msg)->scts = 1;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&(*msg)->ser_name, &conn->cfg->ser_name))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_config_curve_preferences(&(*msg)->supported_curves))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&(*msg)->supported_points, 1))) {
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&(*msg)->supported_points) = 0;
    (*msg)->next_proto_neg = !gquic_list_head_empty(&conn->cfg->next_protos);
    (*msg)->secure_regegotiation_supported = 1;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_copy(&(*msg)->alpn_protos, &conn->cfg->next_protos, gquic_proto_copy))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_copy(&(*msg)->supported_versions, &supported_versions, NULL))) {
        goto failure;
    }
    count = sizeof(__cipher_suites) / sizeof(u_int16_t);
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &cipher_suite, sizeof(u_int16_t)))) {
            goto failure;
        }
        *cipher_suite = __cipher_suites[i];
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&(*msg)->cipher_suites, cipher_suite))) {
            goto failure;
        }
    }
    RAND_bytes(GQUIC_STR_VAL(&(*msg)->random), GQUIC_STR_SIZE(&(*msg)->random));
    RAND_bytes(GQUIC_STR_VAL(&(*msg)->sess_id), GQUIC_STR_SIZE(&(*msg)->sess_id));
    if ((*msg)->vers >= GQUIC_TLS_VERSION_12) {
        count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = NULL;
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &sigalg, sizeof(u_int16_t)))) {
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&(*msg)->supported_sign_algos, sigalg))) {
                goto failure;
            }
        }
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_handshake_client_hello_edch_params_init(params, *msg, conn->cfg))) {
        goto failure;
    }

    while (!gquic_list_head_empty(&supported_versions)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_versions));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    while (!gquic_list_head_empty(&supported_versions)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_versions));
    }
    if (*msg != NULL) {
        gquic_tls_msg_release(*msg);
    }
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_proto_copy(void *proto, const void *ref_proto) {
    if (proto == NULL || ref_proto == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(proto, ref_proto));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_handshake_client_hello_edch_params_init(gquic_tls_ecdhe_params_t *const params,
                                                             gquic_tls_client_hello_msg_t *const msg,
                                                             const gquic_tls_config_t *const cfg) {
    gquic_tls_key_share_t *ks = NULL;
    int exception = GQUIC_SUCCESS;
    if (params == NULL || msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (*((u_int16_t *) GQUIC_LIST_FIRST(&msg->supported_versions)) == GQUIC_TLS_VERSION_13) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_generate(params, GQUIC_TLS_CURVE_X25519))) {
            goto failure;
        }
        gquic_tls_key_share_t *ks = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &ks, sizeof(gquic_tls_key_share_t)))) {
            goto failure;
        }
        gquic_list_head_init(&GQUIC_LIST_META(ks));
        ks->group = GQUIC_TLS_CURVE_X25519;
        gquic_str_init(&ks->data);
        if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(params, &ks->data))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&msg->key_shares, ks))) {
            goto failure;
        }
        if (cfg->extensions != NULL
            && GQUIC_ASSERT_CAUSE(exception, cfg->extensions(&msg->extensions, cfg->ext_self, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO))) {
            goto failure;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_ecdhe_params_dtor(params);
    if (ks != NULL) {
        gquic_list_release(ks);
    }
    GQUIC_PROCESS_DONE(exception);
}

int gquic_tls_client_handshake(gquic_coroutine_t *const co, gquic_tls_conn_t *const conn) {
    gquic_tls_handshake_client_state_t cli_state;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t cache_key = { 0, NULL };
    gquic_tls_client_sess_state_t *sess = NULL;
    size_t _ = 0;
    int exception = GQUIC_SUCCESS;
    if (conn == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->cfg == NULL) {
        gquic_tls_config_default(&conn->cfg);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_client_state_init(&cli_state));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_set_alt_record(conn));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_handshake_client_hello_init(&cli_state.c_hello, &cli_state.ecdhe_params, conn));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_load_session(&cache_key, &sess, &cli_state.early_sec, &cli_state.binder_key, conn, cli_state.c_hello));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_combine_serialize(&buf, cli_state.c_hello));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, (void **) &cli_state.s_hello, conn))
        || GQUIC_TLS_MSG_META(cli_state.s_hello).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
       goto failure;
    }
    if (conn->ver != GQUIC_TLS_VERSION_13) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
        goto failure;
    }
    cli_state.conn = conn;
    cli_state.sess = sess;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_handshake(co, &cli_state))) {
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&cache_key);
    gquic_tls_handshake_client_state_dtor(&cli_state);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&buf);
    gquic_str_reset(&cache_key);
    gquic_tls_handshake_client_state_dtor(&cli_state);
    GQUIC_PROCESS_DONE(exception);
}

int gquic_tls_client_handshake_state_handshake(gquic_coroutine_t *const co, gquic_tls_handshake_client_state_t *const cli_state) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t buf = { 0, NULL };
    if (cli_state == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->conn->handshakes > 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_PROTOCOL_VERSION);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HANDSHAKE_DONE);
    }
    // note: unsupported RSA KA
    if (cli_state->ecdhe_params.self == NULL
        || (!gquic_list_head_empty(&cli_state->c_hello->key_shares)
            && GQUIC_LIST_FIRST(&cli_state->c_hello->key_shares) != gquic_list_prev(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->key_shares)))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(cli_state));
    GQUIC_ASSERT_FAST_RETURN(cli_state->suite->mac(&cli_state->transport, 0, NULL));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, cli_state->c_hello))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        goto failure;
    }
    if (gquic_str_cmp(&cli_state->s_hello->random, gquic_tls_hello_retry_request_random()) == 0) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_process_hello_retry_request(co, cli_state))) {
            goto failure;
        }
    }
    gquic_str_reset(&buf);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, cli_state->s_hello))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        goto failure;
    }

    cli_state->conn->buffering = 1;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_process_server_hello(cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_establish_handshake_keys(cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_read_ser_params(co, cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_read_ser_cert(co, cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_read_ser_finished(co, cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_send_cli_cert(cli_state))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_send_cli_finished(cli_state))) {
        goto failure;
    }
    cli_state->conn->handshake_status = 1;
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(gquic_tls_handshake_client_state_t *const cli_state) {
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->s_hello->supported_version == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_MISSING_EXTENSION);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_VERSION);
    }
    if (cli_state->s_hello->supported_version != GQUIC_TLS_VERSION_13) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
    }
    if (cli_state->s_hello->next_proto_neg
        || !gquic_list_head_empty(&cli_state->s_hello->next_protos)
        || cli_state->s_hello->ocsp_stapling
        || cli_state->s_hello->ticket_supported
        || cli_state->s_hello->secure_regegotiation_supported
        || GQUIC_STR_SIZE(&cli_state->s_hello->secure_regegotation) != 0
        || GQUIC_STR_SIZE(&cli_state->s_hello->alpn_proto) != 0
        || !gquic_list_head_empty(&cli_state->s_hello->scts)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_EXTENSION);
    }
    if (gquic_str_cmp(&cli_state->c_hello->sess_id, &cli_state->s_hello->sess_id) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (cli_state->s_hello->compression_method != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (gquic_tls_choose_cipher_suite(&cipher_suite, &cli_state->c_hello->cipher_suites, cli_state->s_hello->cipher_suite) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (cipher_suite == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (cli_state->suite != NULL && cli_state->suite != cipher_suite) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    cli_state->suite = cipher_suite;
    cli_state->conn->cipher_suite = cipher_suite->id;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_handshake_client_state_dtor(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->s_hello != NULL) {
        gquic_tls_msg_release(cli_state->s_hello);
    }
    if (cli_state->c_hello != NULL) {
        gquic_tls_msg_release(cli_state->c_hello);
    }
    gquic_tls_ecdhe_params_dtor(&cli_state->ecdhe_params);
    gquic_str_reset(&cli_state->early_sec);
    gquic_str_reset(&cli_state->binder_key);
    if (cli_state->cert_req != NULL) {
        gquic_tls_msg_release(cli_state->cert_req);
    }
    gquic_tls_mac_dtor(&cli_state->transport);
    gquic_str_reset(&cli_state->master_sec);
    gquic_str_reset(&cli_state->traffic_sec);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(gquic_tls_handshake_client_state_t *const cli_state) {
    u_int8_t record_payload[] = { 0x01 };
    gquic_str_t record = { sizeof(record_payload), record_payload };
    size_t _;
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->sent_dummy_ccs) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    cli_state->sent_dummy_ccs = 1;
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_write_record(&_, cli_state->conn, GQUIC_TLS_RECORD_TYPE_CHANGE_CIPHER_SEPC, &record));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_client_handshake_state_process_hello_retry_request(gquic_coroutine_t *const co,
                                                                        gquic_tls_handshake_client_state_t *const cli_state) {
    u_int16_t curve_id = 0;
    int supported_curve = 0;
    u_int16_t *c_curve_id = NULL;
    gquic_tls_key_share_t *key_share = NULL;
    int exception = GQUIC_SUCCESS;
    gquic_str_t sh_buf = { 0, NULL };
    gquic_str_t ch_buf = { 0, NULL };
    gquic_str_t ch_hash = { 0, NULL };
    size_t _;
    if (cli_state == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_mac_md_sum(&ch_hash, &cli_state->transport));
    const u_int8_t msg_hash_header_cnt[] = { GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH, 0, 0, (u_int8_t) GQUIC_STR_SIZE(&ch_hash) };
    const gquic_str_t msg_hash_header = { 4, (void *) msg_hash_header_cnt };
    gquic_tls_mac_md_update(&cli_state->transport, &msg_hash_header);
    gquic_tls_mac_md_update(&cli_state->transport, &ch_hash);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_msg_combine_serialize(&sh_buf, cli_state->s_hello));
    gquic_tls_mac_md_update(&cli_state->transport, &sh_buf);

    if (cli_state->s_hello->ser_share.group != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_DECODE_ERROR);
    }
    if ((curve_id = cli_state->s_hello->selected_group) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_MISSING_EXTENSION);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_MISSION_EXTENSION);
    }
    GQUIC_LIST_FOREACH(c_curve_id, &cli_state->c_hello->supported_curves) {
        if (*c_curve_id == curve_id) {
            supported_curve = 1;
            break;
        }
    }
    if (supported_curve == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(&cli_state->ecdhe_params) == curve_id) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_UNNECESSARY_HRR_MESSAGE);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_dtor(&cli_state->ecdhe_params)))  {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_init(&cli_state->ecdhe_params))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_generate(&cli_state->ecdhe_params, curve_id))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &key_share, sizeof(gquic_tls_key_share_t)))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    key_share->group = curve_id;
    gquic_str_init(&key_share->data);
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&cli_state->ecdhe_params, &key_share->data))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    gquic_list_insert_before(&cli_state->c_hello->key_shares, key_share);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&cli_state->c_hello->cookie, &cli_state->s_hello->cookie))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    key_share = NULL;

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&ch_buf, cli_state->c_hello))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (!gquic_list_head_empty(&cli_state->c_hello->psk_identities)) {
        const gquic_tls_cipher_suite_t *psk_suite = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_get_cipher_suite(&psk_suite, cli_state->sess->cipher_suite)) || psk_suite == NULL) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            goto failure;
        }
        if (psk_suite->hash == cli_state->suite->hash) {
            int64_t ticket_age = 0;
            gquic_time_since_milli(&ticket_age, &cli_state->sess->received_at);
            gquic_tls_psk_identity_t *psk_identity = GQUIC_LIST_FIRST(&cli_state->c_hello->psk_identities);
            psk_identity->obfuscated_ticket_age = ticket_age + cli_state->sess->age_add;

            gquic_tls_mac_t transport;
            gquic_tls_mac_init(&transport);
            cli_state->suite->mac(&transport, 0, NULL);

            u_int8_t msg_hash_header_cnt[] = { GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH, 0, 0, (u_int8_t) GQUIC_STR_SIZE(&ch_hash) }; 
            const gquic_str_t msg_hash_header = { 4, (void *) msg_hash_header_cnt };
            const gquic_str_t ch_buf_without_binder = {
                gquic_tls_client_hello_msg_size_without_binders(cli_state->c_hello),
                GQUIC_STR_VAL(&ch_buf)
            };
            gquic_tls_mac_md_update(&transport, &msg_hash_header);
            gquic_tls_mac_md_update(&transport, &ch_hash);
            gquic_tls_mac_md_update(&transport, &sh_buf);
            gquic_tls_mac_md_update(&transport, &ch_buf_without_binder);
            gquic_str_t binder = { 0, NULL };
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_sum(&binder, &transport))) {
                gquic_tls_mac_dtor(&transport);
                goto failure;
            }
            gquic_tls_mac_dtor(&transport);

            size_t origin_psk_binders_count = 0;
            void *_;
            GQUIC_LIST_FOREACH(_, &cli_state->c_hello->psk_binders) origin_psk_binders_count++;
            if (origin_psk_binders_count != 0) {
                GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
                gquic_str_reset(&binder);
                goto failure;
            }
            gquic_str_t *psk_binder = GQUIC_LIST_FIRST(&cli_state->c_hello->psk_binders);
            if (GQUIC_STR_SIZE(psk_binder) != GQUIC_STR_SIZE(&binder)) {
                GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
                gquic_str_reset(&binder);
                goto failure;
            }
            gquic_str_reset(psk_binder);
            psk_binder->val = GQUIC_STR_VAL(&binder);
        }
        else {
            while (!gquic_list_head_empty(&cli_state->c_hello->psk_identities)) {
                gquic_tls_psk_identity_t *removed = GQUIC_LIST_FIRST(&cli_state->c_hello->psk_identities);
                gquic_str_reset(&removed->label);
                gquic_list_release(removed);
            }
            while (!gquic_list_head_empty(&cli_state->c_hello->psk_binders)) {
                gquic_str_t *binder = GQUIC_LIST_FIRST(&cli_state->c_hello->psk_binders);
                gquic_str_reset(binder);
                gquic_list_release(binder);
            }
        }
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&_, cli_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &ch_buf))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (cli_state->s_hello != NULL) {
        gquic_tls_msg_release(cli_state->s_hello);
        cli_state->s_hello = NULL;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, (void **) &cli_state->s_hello, cli_state->conn))
        || GQUIC_TLS_MSG_META(cli_state->s_hello).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(cli_state))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_str_reset(&sh_buf);
    gquic_str_reset(&ch_buf);
    gquic_str_reset(&ch_hash);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (key_share != NULL) {
        if (GQUIC_STR_SIZE(&key_share->data) != 0) {
            gquic_str_reset(&key_share->data);
        }
        gquic_list_release(key_share);
    }
    gquic_str_reset(&sh_buf);
    gquic_str_reset(&ch_buf);
    gquic_str_reset(&ch_hash);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_process_server_hello(gquic_tls_handshake_client_state_t *const cli_state) {
    int exception = GQUIC_SUCCESS;
    const gquic_tls_cipher_suite_t *psk_suite = NULL;
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    if (gquic_str_cmp(&cli_state->s_hello->random, gquic_tls_hello_retry_request_random()) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_SEND_TWO_HRR);
    }
    if (GQUIC_STR_SIZE(&cli_state->s_hello->cookie) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_EXTENSION);
    }
    if (cli_state->s_hello->selected_group != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_DECODE_ERROR);
    }
    if (cli_state->s_hello->ser_share.group == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (cli_state->s_hello->ser_share.group != GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(&cli_state->ecdhe_params)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (!cli_state->s_hello->selected_identity_persent) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    u_int16_t cli_psk_identities_count = ({
                                          u_int16_t ret = 0;
                                          void *_;
                                          GQUIC_LIST_FOREACH(_, &cli_state->c_hello->psk_identities) ret++;
                                          ret;
                                          });
    if (cli_state->s_hello->selected_identity >= cli_psk_identities_count) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (cli_psk_identities_count != 1 || cli_state->sess == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_get_cipher_suite(&psk_suite, cli_state->sess->cipher_suite))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_PROCESS_DONE(exception);
    }
    if (psk_suite->mac != cli_state->suite->mac) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
    }
    cli_state->using_psk = 1;
    cli_state->conn->did_resume = 1;
    gquic_list_copy(&cli_state->conn->peer_certs, &cli_state->sess->ser_certs, NULL);
    gquic_list_copy(&cli_state->conn->verified_chains, &cli_state->sess->verified_chains, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_client_handshake_state_establish_handshake_keys(gquic_tls_handshake_client_state_t *const cli_state) {
    int exception = GQUIC_SUCCESS;
    gquic_str_t shared_key = { 0, NULL };
    gquic_str_t early_sec = { 0, NULL };
    gquic_str_t handshake_sec = { 0, NULL };
    gquic_str_t cli_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    gquic_str_t early_sec_derived_sec = { 0, NULL };
    gquic_str_t handshake_sec_derived_sec = { 0, NULL };
    static const gquic_str_t derived_label = { 7, "derived" };
    static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&cli_state->ecdhe_params, &shared_key, &cli_state->s_hello->ser_share.data))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&shared_key) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&early_sec, &cli_state->early_sec))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (!cli_state->using_psk) {
        gquic_str_reset(&early_sec);
        gquic_tls_cipher_suite_extract(&early_sec, cli_state->suite, NULL, NULL);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, cli_state->suite, NULL, &early_sec, &derived_label))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_extract(&handshake_sec, cli_state->suite, &shared_key, &early_sec_derived_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&cli_sec,
                                                                cli_state->suite,
                                                                &cli_state->transport, &handshake_sec, &cli_handshake_traffic_label))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&cli_state->conn->out, GQUIC_ENC_LV_HANDSHAKE, cli_state->suite, &cli_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->out, cli_state->suite, &cli_sec, 0))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                                                cli_state->suite,
                                                                &cli_state->transport, &handshake_sec, &ser_handshake_traffic_label))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&cli_state->conn->in, GQUIC_ENC_LV_HANDSHAKE, cli_state->suite, &ser_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->in, cli_state->suite, &ser_sec, 1))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&handshake_sec_derived_sec,
                                                                cli_state->suite,
                                                                NULL, &handshake_sec, &derived_label))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_extract(&cli_state->master_sec, cli_state->suite, NULL, &handshake_sec_derived_sec))) {
        goto failure;
    }

    gquic_str_reset(&shared_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&handshake_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&handshake_sec_derived_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&shared_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&handshake_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&handshake_sec_derived_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_read_ser_params(gquic_coroutine_t *const co, gquic_tls_handshake_client_state_t *const cli_state) {
    gquic_tls_encrypt_ext_msg_t *msg = NULL;
    gquic_str_t buf = { 0, NULL };
    int exception = GQUIC_SUCCESS;
    if (cli_state == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, (void **) &msg, cli_state->conn))
        || GQUIC_TLS_MSG_META(msg).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        goto failure;
    }
    if (cli_state->conn->cfg->received_extensions != NULL
        && GQUIC_ASSERT_CAUSE(exception,
                              cli_state->conn->cfg->received_extensions(cli_state->conn->cfg->ext_self,
                                                                        GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS,
                                                                        &msg->addition_exts))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, msg))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0 && gquic_list_head_empty(&cli_state->c_hello->alpn_protos)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_UNSUPPORT_EXTENSION);
        goto failure;
    }
    if (cli_state->conn->cfg->enforce_next_proto_selection) {
        if (GQUIC_STR_SIZE(&msg->alpn_proto) == 0) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_NO_APP_PROTOCOL);
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, mutual_protocol(&msg->alpn_proto, &cli_state->conn->cfg->next_protos))) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
            goto failure;
        }
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(&cli_state->conn->cli_proto, &msg->alpn_proto))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_tls_msg_release(msg);
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_msg_release(msg);
    gquic_str_reset(&buf);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_read_ser_cert(gquic_coroutine_t *const co, gquic_tls_handshake_client_state_t *const cli_state) {
    static const gquic_str_t ser_sign_cnt = { 38, "GQUIC-TLSv1.3, server SignatureContent" };
    int exception = GQUIC_SUCCESS;
    void *msg = NULL;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t sign = { 0, NULL };
    gquic_tls_cert_msg_t *cert_msg = NULL;
    gquic_tls_cert_verify_msg_t *verify_msg = NULL;
    gquic_list_t supported_sigalgs;
    const EVP_MD *sig_hash = NULL;
    EVP_PKEY *pubkey = NULL;
    if (cli_state == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->using_psk) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    {
        gquic_list_head_init(&supported_sigalgs);
        size_t count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        size_t i;
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = NULL;
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &sigalg, sizeof(u_int16_t)))) {
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&supported_sigalgs, sigalg))) {
                goto failure;
            }
        }
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, &msg, cli_state->conn))) {
        goto failure;
    }
    if (GQUIC_TLS_MSG_META(msg).type == GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, msg))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
            gquic_tls_msg_release(msg);
            goto failure;
        }
        cli_state->cert_req = msg;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, &msg, cli_state->conn))) {
            goto failure;
        }
    }
    if (GQUIC_TLS_MSG_META(msg).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_HANDSHAKE_MESSAGE_UNEXCEPTED);
        goto failure;
    }
    cert_msg = msg;
    if (gquic_list_head_empty(&cert_msg->cert.certs)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_DECODE_ERROR);
        goto failure;
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, cert_msg))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    gquic_str_reset(&buf);

    // TODO ocsp && scts

    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_verify_ser_cert(cli_state->conn, &cert_msg->cert.certs))) {
        goto failure;
    }

    gquic_str_init(&buf);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, (void **) &verify_msg, cli_state->conn))
        || GQUIC_TLS_MSG_META(verify_msg).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        goto failure;
    }
    if (gquic_tls_is_supported_sigalg(verify_msg->sign_algo, &supported_sigalgs) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hash_from_sigalg(&sig_hash, verify_msg->sign_algo))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    const u_int8_t sig_type = gquic_tls_sig_from_sigalg(verify_msg->sign_algo);
    if (sig_type == 0xff) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INTERNAL_ERROR);
        goto failure;
    }
    if (sig_type == GQUIC_SIG_PKCS1V15 || sig_hash == EVP_sha1()) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ILLEGAL_PARAMERTERS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_signed_msg(&sign, sig_hash, &ser_sign_cnt, &cli_state->transport))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_sig_pubkey_from_x509(&pubkey, sig_type, *(X509 **) GQUIC_LIST_FIRST(&cli_state->conn->peer_certs)))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_verify_handshake_sign(sig_hash, pubkey, &sign, &verify_msg->sign))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, verify_msg))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&sign);
    if (cert_msg != NULL) {
        gquic_tls_msg_release(cert_msg);
    }
    if (verify_msg != NULL) {
        gquic_tls_msg_release(verify_msg);
    }
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    while (!gquic_list_head_empty(&supported_sigalgs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_sigalgs));
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&buf);
    gquic_str_reset(&sign);
    if (cert_msg != NULL) {
        gquic_tls_msg_release(cert_msg);
    }
    if (verify_msg != NULL) {
        gquic_tls_msg_release(verify_msg);
    }
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    while (!gquic_list_head_empty(&supported_sigalgs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_sigalgs));
    }
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_read_ser_finished(gquic_coroutine_t *const co, gquic_tls_handshake_client_state_t *const cli_state) {
    int exception = GQUIC_SUCCESS;
    static const gquic_str_t cli_app_traffic_label = { 12, "c ap traffic" };
    static const gquic_str_t ser_app_traffic_label = { 12, "s ap traffic" };
    gquic_tls_finished_msg_t *msg = NULL;
    gquic_str_t expected_mac = { 0, NULL };
    gquic_str_t buf = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    if (cli_state == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_read_handshake(co, (void **) &msg, cli_state->conn))
        || GQUIC_TLS_MSG_META(msg).type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        GQUIC_PROCESS_DONE(exception);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_finished_hash(&expected_mac,
                                                                  cli_state->suite,
                                                                  &cli_state->conn->in.traffic_sec, &cli_state->transport));
    if (gquic_str_cmp(&expected_mac, &msg->verify) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_DECODE_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, msg))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&cli_state->traffic_sec,
                                                                cli_state->suite,
                                                                &cli_state->transport, &cli_state->master_sec, &cli_app_traffic_label))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                                                cli_state->suite,
                                                                &cli_state->transport,
                                                                &cli_state->master_sec,
                                                                &ser_app_traffic_label))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_key(&cli_state->conn->in, GQUIC_ENC_LV_APP, cli_state->suite, &ser_sec))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->in, cli_state->suite, &ser_sec, 1))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_cipher_suite_export_keying_material(&cli_state->conn->ekm,
                                                                         cli_state->suite, &cli_state->master_sec, &cli_state->transport))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        goto failure;
    }

    if (msg != NULL) {
        gquic_tls_msg_release(msg);
    }
    gquic_str_reset(&expected_mac);
    gquic_str_reset(&buf);
    gquic_str_reset(&ser_sec);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (msg != NULL) {
        gquic_tls_msg_release(msg);
    }
    gquic_str_reset(&expected_mac);
    gquic_str_reset(&buf);
    gquic_str_reset(&ser_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int gquic_tls_client_handshake_state_send_cli_cert(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cli_state->cert_req == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    // TODO

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_client_handshake_state_send_cli_finished(gquic_tls_handshake_client_state_t *const cli_state) {
    size_t len = 0;
    int exception = GQUIC_SUCCESS;
    gquic_tls_finished_msg_t *finished = NULL;
    gquic_str_t buf = { 0, NULL };
    static const gquic_str_t resumption_label = { 10, "res master" };
    if (cli_state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_finished_msg_alloc(&finished));
    GQUIC_TLS_MSG_INIT(finished);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_finished_hash(&finished->verify,
                                             cli_state->suite,
                                             &cli_state->conn->out.traffic_sec, &cli_state->transport));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(&buf, finished))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_mac_md_update(&cli_state->transport, &buf))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_conn_write_record(&len, cli_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_half_conn_set_key(&cli_state->conn->out, GQUIC_ENC_LV_APP, cli_state->suite, &cli_state->traffic_sec))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->out, cli_state->suite, &cli_state->traffic_sec, 0))) {
        goto failure;
    }

    if (!cli_state->conn->cfg->sess_ticket_disabled && cli_state->conn->cfg->cli_sess_cache != NULL) {
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_tls_cipher_suite_derive_secret(&cli_state->conn->resumption_sec,
                                                                    cli_state->suite,
                                                                    &cli_state->transport, &cli_state->master_sec, &resumption_label))) {
            goto failure;
        }
    }

    gquic_str_reset(&buf);
    gquic_tls_msg_release(finished);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&buf);
    gquic_tls_msg_release(finished);
    GQUIC_PROCESS_DONE(exception);
}

static int mutual_protocol(const gquic_str_t *const proto, const gquic_list_t *const perfer_protos) {
    if (proto == NULL || perfer_protos == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_t *perfer_proto = NULL;

    GQUIC_LIST_FOREACH(perfer_proto, perfer_protos) {
        if (gquic_str_cmp(proto, perfer_proto) == 0) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
}


#include "tls/handshake_server.h"
#include "tls/alert.h"
#include "tls/key_schedule.h"
#include "tls/server_hello_msg.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/auth.h"
#include "tls/cert_13_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/finished_msg.h"
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

static int mutual_protocol(const gquic_str_t **const, const gquic_list_t *const, const gquic_list_t *const);
static int gquic_tls_handshake_server_state_request_cli_cert(gquic_tls_handshake_server_state_t *const);

static u_int16_t __cipher_suites[] = {
    GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384
};

int gquic_tls_handshake_server_state_init(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }

    ser_state->conn = NULL;
    ser_state->c_hello = NULL;
    ser_state->s_hello = NULL;
    ser_state->sent_dummy_ccs = 0;
    ser_state->using_psk = 0;
    ser_state->suite = NULL;
    gquic_str_init(&ser_state->cert);
    ser_state->sigalg = 0;
    gquic_str_init(&ser_state->early_sec);
    gquic_str_init(&ser_state->shared_key);
    gquic_str_init(&ser_state->handshake_sec);
    gquic_str_init(&ser_state->master_sec);
    gquic_str_init(&ser_state->traffic_sec);
    gquic_tls_mac_init(&ser_state->transport);
    gquic_str_init(&ser_state->cli_finished);

    return 0;
}

int gquic_tls_handshake_server_state_release(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }
    if (ser_state->c_hello != NULL) {
        gquic_tls_client_hello_msg_reset(ser_state->c_hello);
        free(ser_state->c_hello);
    }
    if (ser_state->s_hello != NULL) {
        gquic_tls_server_hello_msg_reset(ser_state->s_hello);
        free(ser_state->s_hello);
    }
    gquic_str_reset(&ser_state->cert);
    gquic_str_reset(&ser_state->early_sec);
    gquic_str_reset(&ser_state->shared_key);
    gquic_str_reset(&ser_state->handshake_sec);
    gquic_str_reset(&ser_state->master_sec);
    gquic_str_reset(&ser_state->traffic_sec);
    gquic_tls_mac_release(&ser_state->transport);
    gquic_str_reset(&ser_state->cli_finished);
    return 0;
}

int gquic_tls_server_handshake(gquic_tls_conn_t *const conn) {
    int ret = 0;
    u_int8_t handshake_type = 0;
    gquic_tls_handshake_server_state_t ser_state;
    if (conn == NULL) {
        return -1;
    }
    gquic_tls_handshake_server_state_init(&ser_state);
    ser_state.conn = conn;
    if (gquic_tls_conn_set_alt_record(conn) != 0) {
        return -2;
    }
    if (gquic_tls_conn_read_handshake(&handshake_type, (void **) &ser_state.c_hello, conn) != 0) {
        return -3;
    }
    if (handshake_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, handshake_type, ser_state.c_hello);
        return -4;
    }
    if ((ret = gquic_tls_server_handshake_state_handshake(&ser_state)) != 0) {
        gquic_tls_handshake_server_state_release(&ser_state);
        return -5 + ret * 100;
    }
    
    gquic_tls_handshake_server_state_release(&ser_state);
    return 0;
}

int gquic_tls_server_handshake_state_handshake(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    if (ser_state == NULL) {
        return -1;
    }

    if ((ret = gquic_tls_handshake_server_state_process_cli_hello(ser_state)) != 0) {
        return -2 + ret * 100;
    }
    if (gquic_tls_handshake_server_state_check_for_resumption(ser_state) != 0) {
        return -3;
    }
    if (gquic_tls_handshake_server_state_pick_cert(ser_state) != 0) {
        return -4;
    }
    ser_state->conn->buffering = 1;
    if (gquic_tls_handshake_server_state_send_ser_params(ser_state) != 0) {
        return -5;
    }
    if (gquic_tls_handshake_server_state_send_ser_cert(ser_state) != 0) {
        return -6;
    }
    if (gquic_tls_handshake_server_state_send_ser_finished(ser_state) != 0) {
        return -7;
    }
    if (gquic_tls_handshake_server_state_read_cli_cert(ser_state) != 0) {
        return -8;
    }
    if (gquic_tls_handshake_server_state_read_cli_finished(ser_state) != 0) {
        return -9;
    }

    ser_state->conn->handshake_status = 1;

    return 0;
}

static int gquic_tls_handshake_server_state_process_cli_hello(gquic_tls_handshake_server_state_t *const ser_state) {
    size_t count;
    size_t i;
    int ret = 0;
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
        return -1;
    }
    gquic_list_head_init(&default_cipher_suites);
    gquic_list_head_init(&curve_perfers);
    gquic_tls_ecdhe_params_init(&ecdhe_param);

    count = sizeof(__cipher_suites) / sizeof(u_int16_t);
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = gquic_list_alloc(sizeof(u_int16_t));
        if (cipher_suite == NULL) {
            ret = -2;
            goto failure;
        }
        *cipher_suite = __cipher_suites[i];
        if (gquic_list_insert_before(&default_cipher_suites, cipher_suite) != 0) {
            ret = -3;
            goto failure;
        }
    }

    if ((ser_state->s_hello = malloc(sizeof(gquic_tls_server_hello_msg_t))) == NULL) {
        ret = -4;
        goto failure;
    }
    gquic_tls_server_hello_msg_init(ser_state->s_hello);
    ser_state->s_hello->vers = GQUIC_TLS_VERSION_13;
    ser_state->s_hello->supported_version = ser_state->c_hello->vers;

    if (gquic_list_head_empty(&ser_state->c_hello->supported_versions)) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -5;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->c_hello->compression_methods) != 1
        || ((u_int8_t *) GQUIC_STR_VAL(&ser_state->c_hello->compression_methods))[0] != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -6;
        goto failure;
    }
    if (gquic_str_alloc(&ser_state->s_hello->random, 32) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (RAND_bytes(GQUIC_STR_VAL(&ser_state->s_hello->random), 32) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->c_hello->secure_regegotation) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        ret = -9;
        goto failure;
    }
    if (ser_state->c_hello->early_data) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        ret = -10;
        goto failure;
    }
    if (gquic_str_copy(&ser_state->s_hello->sess_id, &ser_state->c_hello->sess_id) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    ser_state->s_hello->compression_method = 0;
    GQUIC_LIST_FOREACH(suite_id, (ser_state->conn->cfg->ser_perfer_cipher_suite ? &default_cipher_suites : &ser_state->c_hello->cipher_suites)) {
        gquic_list_t *supported = ser_state->conn->cfg->ser_perfer_cipher_suite ? &ser_state->c_hello->cipher_suites : &default_cipher_suites;
        if (gquic_tls_choose_cipher_suite(&ser_state->suite, supported, *suite_id) == 0) {
            break;
        }
    }
    if (ser_state->suite == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_HANDSHAKE_FAILURE);
        ret = -12;
        goto failure;
    }
    ser_state->conn->cipher_suite = ser_state->suite->id;
    ser_state->s_hello->cipher_suite = ser_state->suite->id;
    if (ser_state->suite->mac(&ser_state->transport, GQUIC_TLS_VERSION_13, NULL) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    if (gquic_tls_config_curve_preferences(&curve_perfers) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
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
        ret = -15;
        goto failure;
    }
    if (cli_key_share == NULL) {
        if (gquic_tls_handshake_server_state_do_hello_retry_req(ser_state, selected_group) != 0) {
            ret = -16;
            goto failure;
        }
        cli_key_share = GQUIC_LIST_FIRST(&ser_state->c_hello->key_shares);
    }
    if (gquic_tls_ecdhe_params_generate(&ecdhe_param, selected_group) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -17;
        goto failure;
    }
    ser_state->s_hello->ser_share.group = selected_group;
    if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_param, &ser_state->s_hello->ser_share.data) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -18;
        goto failure;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_param, &ser_state->shared_key, &cli_key_share->data) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -19;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->shared_key) == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -20;
        goto failure;
    }
    if (gquic_str_copy(&ser_state->conn->ser_name, &ser_state->c_hello->ser_name) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -21;
        goto failure;
    }

    if (ser_state->conn->cfg->received_extensions != 0) {
        ser_state->conn->cfg->received_extensions(GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO, &ser_state->c_hello->extensions);
    }

    while (!gquic_list_head_empty(&default_cipher_suites)) {
        gquic_list_release(GQUIC_LIST_FIRST(&default_cipher_suites));
    }
    while (!gquic_list_head_empty(&curve_perfers)) {
        gquic_list_release(GQUIC_LIST_FIRST(&curve_perfers));
    }
    gquic_tls_ecdhe_params_release(&ecdhe_param);
    return 0;
failure:
    while (!gquic_list_head_empty(&default_cipher_suites)) {
        gquic_list_release(GQUIC_LIST_FIRST(&default_cipher_suites));
    }
    while (!gquic_list_head_empty(&curve_perfers)) {
        gquic_list_release(GQUIC_LIST_FIRST(&curve_perfers));
    }
    gquic_tls_ecdhe_params_release(&ecdhe_param);
    return ret;
}

static int gquic_tls_handshake_server_state_do_hello_retry_req(gquic_tls_handshake_server_state_t *const ser_state, const u_int16_t selected_group) {
    int ret = 0;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t c_hash = { 0, NULL };
    gquic_tls_server_hello_msg_t hello_retry_req;
    gquic_tls_client_hello_msg_t *c_hello = NULL;
    u_int8_t c_hello_msg_type = 0;
    size_t _;
    if (ser_state == NULL) {
        return -1;
    }
    gquic_tls_server_hello_msg_init(&hello_retry_req);
    if (gquic_str_alloc(&buf, gquic_tls_client_hello_msg_size(ser_state->c_hello)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -2;
        goto failure;
    }
    if (gquic_tls_client_hello_msg_serialize(ser_state->c_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -3;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_tls_mac_md_sum(&c_hash, &ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_mac_md_reset(&ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    const u_int8_t hash_cnt[] = { GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH, 0, 0, (u_int8_t) GQUIC_STR_SIZE(&c_hash) };
    const gquic_str_t hash = { sizeof(hash_cnt), (void *) hash_cnt };
    if (gquic_tls_mac_md_update(&ser_state->transport, &hash) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &c_hash) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }

    hello_retry_req.vers = ser_state->s_hello->vers;
    if (gquic_str_copy(&hello_retry_req.random, gquic_tls_hello_retry_request_random()) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -9;
        goto failure;
    }
    if (gquic_str_copy(&hello_retry_req.sess_id, &ser_state->s_hello->sess_id) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -10;
        goto failure;
    }
    hello_retry_req.cipher_suite = ser_state->s_hello->cipher_suite;
    hello_retry_req.compression_method = ser_state->s_hello->compression_method;
    hello_retry_req.supported_version = ser_state->s_hello->supported_version;
    hello_retry_req.selected_group = ser_state->s_hello->selected_group;

    gquic_str_reset(&buf);
    gquic_str_init(&buf);

    if (gquic_str_alloc(&buf, gquic_tls_server_hello_msg_size(&hello_retry_req)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_server_hello_msg_serialize(&hello_retry_req, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if (gquic_tls_handshake_server_state_send_dummy_change_cipher_spec(ser_state) != 0) {
        ret = -15;
        goto failure;
    }
    if (gquic_tls_conn_read_handshake(&c_hello_msg_type, (void **) &c_hello, ser_state->conn) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -16;
        goto failure;
    }
    if (c_hello_msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, c_hello_msg_type, c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        ret = -17;
        goto failure;
    }
    if ((!gquic_list_head_empty(&c_hello->key_shares)
         && GQUIC_LIST_FIRST(&c_hello->key_shares) == gquic_list_prev(GQUIC_LIST_PAYLOAD(&c_hello->key_shares)))
        || ((gquic_tls_key_share_t *) GQUIC_LIST_FIRST(&c_hello->key_shares))->group != selected_group) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, c_hello_msg_type, c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -18;
        goto failure;
    }
    if (c_hello->early_data) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, c_hello_msg_type, c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -19;
        goto failure;
    }

    if (gquic_tls_handshake_server_state_illegal_client_hello_change(c_hello, ser_state->c_hello)) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, c_hello_msg_type, c_hello);
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -20;
        goto failure;
    }
    gquic_tls_client_hello_msg_reset(ser_state->c_hello);
    free(ser_state->c_hello);
    ser_state->c_hello = c_hello;

    gquic_str_reset(&buf);
    gquic_str_reset(&c_hash);
    return 0;
failure:

    gquic_str_reset(&buf);
    gquic_str_reset(&c_hash);
    return ret;
}

static int gquic_tls_handshake_server_state_illegal_client_hello_change(gquic_tls_client_hello_msg_t *const c_hello1,
                                                                        gquic_tls_client_hello_msg_t *const c_hello2) {
    if (c_hello1 == NULL || c_hello2 == NULL) {
        return -1;
    }

    // TODO

    return 0;
}

static int gquic_tls_handshake_server_state_send_dummy_change_cipher_spec(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }
    if (ser_state->sent_dummy_ccs) {
        return 0;
    }
    ser_state->sent_dummy_ccs = 1;

    return 0;
}

static int gquic_tls_handshake_server_state_check_for_resumption(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }
    if (ser_state->conn->cfg->sess_ticket_disabled) {
        return 0;
    }
    
    // TODO

    return 0;
}

static int gquic_tls_handshake_server_state_pick_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_list_t supported_algs;
    u_int16_t *perfer_alg = NULL;
    if (ser_state == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -1;
    }
    if (ser_state->using_psk) {
        return 0;
    }
    gquic_list_head_init(&supported_algs);
    if (ser_state->conn->cfg->get_ser_cert(&ser_state->cert, ser_state->c_hello) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -2;
        goto failure;
    }
    if (gquic_tls_sig_schemes_from_cert(&supported_algs, &ser_state->cert) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -3;
        goto failure;
    }
    if (gquic_list_head_empty(&supported_algs)) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
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
        ret = -5;
        goto failure;
    }
    
    while (!gquic_list_head_empty(&supported_algs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_algs));
    }
    return 0;
failure:
    while (!gquic_list_head_empty(&supported_algs)) {
        gquic_list_release(GQUIC_LIST_FIRST(&supported_algs));
    }
    return ret;
}

static int gquic_tls_handshake_server_state_send_ser_params(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t early_sec = { 0, NULL };
    gquic_str_t early_sec_derived_sec = { 0, NULL };
    gquic_str_t cli_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    gquic_tls_encrypt_ext_msg_t enc_ext;
    static const gquic_str_t derived_label = { 7, "derived" };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
    size_t _;
    const gquic_str_t *selected_proto = NULL;
    if (ser_state == NULL) {
        return -1;
    }
    gquic_tls_encrypt_ext_msg_init(&enc_ext);
    if (gquic_str_alloc(&buf, gquic_tls_client_hello_msg_size(ser_state->c_hello)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -2;
        goto failure;
    }
    if (gquic_tls_client_hello_msg_serialize(ser_state->c_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -3;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_str_alloc(&buf, gquic_tls_server_hello_msg_size(ser_state->s_hello)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_server_hello_msg_serialize(ser_state->s_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&ser_state->early_sec) == 0) {
        if (gquic_tls_cipher_suite_extract(&early_sec, ser_state->suite, NULL, NULL) != 0) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            ret = -9;
            goto failure;
        }
    }
    else {
        if (gquic_str_copy(&early_sec, &ser_state->early_sec) != 0) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            ret = -10;
            goto failure;
        }
    }
    if (gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, ser_state->suite, NULL, &early_sec, &derived_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_cipher_suite_extract(&ser_state->handshake_sec, ser_state->suite, &ser_state->shared_key, &early_sec_derived_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&cli_sec, ser_state->suite, &ser_state->transport, &ser_state->handshake_sec, &cli_handshake_traffic_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    if (gquic_tls_half_conn_set_key(&ser_state->conn->in, GQUIC_ENC_LV_APP, ser_state->suite, &cli_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->in, ser_state->suite, &cli_sec, 1) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -15;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&ser_sec, ser_state->suite, &ser_state->transport, &ser_state->handshake_sec, &ser_handshake_traffic_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -16;
        goto failure;
    }
    if (gquic_tls_half_conn_set_key(&ser_state->conn->out, GQUIC_ENC_LV_APP, ser_state->suite, &ser_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->out, ser_state->suite, &ser_sec, 0) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -15;
        goto failure;
    }
    if (!gquic_list_head_empty(&ser_state->c_hello->alpn_protos)) {
        if (mutual_protocol(&selected_proto, &ser_state->c_hello->alpn_protos, &ser_state->conn->cfg->next_protos) == 0) {
            if (gquic_str_copy(&enc_ext.alpn_proto, selected_proto) != 0) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                ret = -16;
                goto failure;
            }
            if (gquic_str_copy(&ser_state->conn->cli_proto, selected_proto) != 0) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                ret = -17;
                goto failure;
            }
        }
    }
    if (ser_state->conn->cfg->enforce_next_proto_selection && GQUIC_STR_SIZE(&ser_state->conn->cli_proto) == 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
        ret = -18;
        goto failure;
    }
    if (ser_state->conn->cfg->extensions != NULL) {
        if (ser_state->conn->cfg->extensions(&enc_ext.addition_exts, GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS) != 0) {
            gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            ret = -19;
            goto failure;
        }
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_str_alloc(&buf, gquic_tls_encrypt_ext_msg_size(&enc_ext)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -20;
        goto failure;
    }
    if (gquic_tls_encrypt_ext_msg_serialize(&enc_ext, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -21;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -22;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -23;
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_tls_encrypt_ext_msg_reset(&enc_ext);
    return 0;
failure:

    gquic_str_reset(&buf);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_tls_encrypt_ext_msg_reset(&enc_ext);
    return ret;
}

static int mutual_protocol(const gquic_str_t **const ret, const gquic_list_t *const protos, const gquic_list_t *const perfer_protos) {
    gquic_str_t *proto = NULL;
    if (protos == NULL || perfer_protos == NULL) {
        return -1;
    }
    gquic_str_t *perfer_proto = NULL;

    GQUIC_LIST_FOREACH(perfer_proto, perfer_protos) {
        GQUIC_LIST_FOREACH(proto, protos) {
            if (gquic_str_cmp(proto, perfer_proto) == 0) {
                *ret = perfer_proto;
                return 0;
            }
        }
    }

    return -2;
}

static int gquic_tls_handshake_server_state_send_ser_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_tls_cert_req_13_msg_t cert_req;
    gquic_tls_cert_13_msg_t cert_msg;
    gquic_tls_cert_verify_msg_t verify_msg;
    gquic_str_t buf = { 0, NULL };
    PKCS12 *cert_p12 = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    u_int8_t *x509_cnt = NULL;
    const u_int8_t *cert_cnt = NULL;
    gquic_str_t *cert = NULL;
    size_t _;
    static const gquic_str_t ser_sign_cnt = { 38, "GQUIC-TLSv1.3, server SignatureContent" };
    if (ser_state == NULL) {
        return -1;
    }
    if (ser_state->using_psk) {
        return 0;
    }
    gquic_tls_cert_req_13_msg_init(&cert_req);
    gquic_tls_cert_13_msg_init(&cert_msg);
    gquic_tls_cert_verify_msg_init(&verify_msg);
    if (gquic_tls_handshake_server_state_request_cli_cert(ser_state)) {
        cert_req.ocsp_stapling = 1;
        cert_req.scts = 1;

        gquic_list_head_init(&cert_req.supported_sign_algo);
        size_t count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        size_t i;
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = gquic_list_alloc(sizeof(u_int16_t));
            if (sigalg == NULL) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                ret = -2;
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (gquic_list_insert_before(&cert_req.supported_sign_algo, sigalg) != 0) {
                gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
                ret = -3;
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
    cert_cnt = GQUIC_STR_VAL(&ser_state->cert);
    if ((cert_p12 = d2i_PKCS12(NULL, &cert_cnt, GQUIC_STR_SIZE(&ser_state->cert))) == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    if (PKCS12_parse(cert_p12, NULL, &pkey, &x509, NULL) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if ((cert = gquic_list_alloc(sizeof(gquic_str_t))) == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    if (gquic_str_alloc(cert, i2d_X509(x509, NULL)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    x509_cnt = GQUIC_STR_VAL(cert);
    if (i2d_X509(x509, &x509_cnt) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }
    if (gquic_list_insert_before(&cert_msg.cert.certs, cert) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -9;
        goto failure;
    }
    if (gquic_str_alloc(&buf, gquic_tls_cert_13_msg_size(&cert_msg)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -10;
        goto failure;
    }
    if (gquic_tls_cert_13_msg_serialize(&cert_msg, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }

    verify_msg.has_sign_algo = 1;
    verify_msg.sign_algo = ser_state->sigalg;
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_tls_signed_msg(&buf, NULL, &ser_sign_cnt, &ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -15;
        goto failure;
    }
    if (EVP_MD_CTX_init(md_ctx) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -16;
        goto failure;
    }
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -17;
        goto failure;
    }
    if (EVP_DigestSign(md_ctx, NULL, &_, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -18;
        goto failure;
    }
    if (gquic_str_alloc(&verify_msg.sign, _) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -19;
        goto failure;
    }
    if (EVP_DigestSign(md_ctx, GQUIC_STR_VAL(&verify_msg.sign), &_, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) <= 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -20;
        goto failure;
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_str_alloc(&buf, gquic_tls_cert_verify_msg_size(&verify_msg)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -21;
        goto failure;
    }
    if (gquic_tls_cert_verify_msg_serialize(&verify_msg, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -22;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -23;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -24;
        goto failure;
    }

    gquic_tls_cert_req_13_msg_reset(&cert_req);
    gquic_tls_cert_13_msg_reset(&cert_msg);
    gquic_tls_cert_verify_msg_reset(&verify_msg);
    gquic_str_reset(&buf);
    if (cert_p12 != NULL) {
        PKCS12_free(cert_p12);
    }
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return 0;
failure:

    gquic_tls_cert_req_13_msg_reset(&cert_req);
    gquic_tls_cert_13_msg_reset(&cert_msg);
    gquic_tls_cert_verify_msg_reset(&verify_msg);
    gquic_str_reset(&buf);
    if (cert_p12 != NULL) {
        PKCS12_free(cert_p12);
    }
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret;
}

static int gquic_tls_handshake_server_state_request_cli_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return 0;
    }
    return ser_state->conn->cfg->cli_auth >= GQUIC_CLI_AUTH_REQ && !ser_state->using_psk;
}

static int gquic_tls_handshake_server_state_send_ser_finished(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_tls_finished_msg_t finished;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t handshake_sec_derived_sec = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    size_t _;
    static const gquic_str_t derived_label = { 7, "derived" };
    static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    if (ser_state == NULL) {
        return -1;
    }
    gquic_tls_finished_msg_init(&finished);
    if (gquic_tls_cipher_suite_finished_hash(&finished.verify,
                                             ser_state->suite,
                                             &ser_state->conn->out.traffic_sec,
                                             &ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -2;
    }
    if (gquic_str_alloc(&buf, gquic_tls_finished_msg_size(&finished)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -3;
        goto failure;
    }
    if (gquic_tls_finished_msg_serialize(&finished, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, ser_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&handshake_sec_derived_sec, ser_state->suite, NULL, &ser_state->handshake_sec, &derived_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (gquic_tls_cipher_suite_extract(&ser_state->master_sec, ser_state->suite, NULL, &handshake_sec_derived_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&ser_state->traffic_sec,
                                             ser_state->suite,
                                             &ser_state->transport,
                                             &ser_state->master_sec,
                                             &cli_handshake_traffic_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -9;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                             ser_state->suite,
                                             &ser_state->transport,
                                             &ser_state->master_sec,
                                             &ser_handshake_traffic_label) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -10;
        goto failure;
    }
    if (gquic_tls_half_conn_set_key(&ser_state->conn->out, GQUIC_ENC_LV_APP, ser_state->suite, &ser_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->out, ser_state->suite, &ser_sec, 0) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    if (gquic_tls_cipher_suite_export_keying_material(&ser_state->conn->ekm,
                                                      ser_state->suite,
                                                      &ser_state->master_sec,
                                                      &ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    if (!gquic_tls_handshake_server_state_request_cli_cert(ser_state)) {
        if (gquic_tls_handshake_server_state_send_session_tickets(ser_state) != 0) {
            ret = -14;
            goto failure;
        }
    }
    
    gquic_tls_finished_msg_reset(&finished);
    gquic_str_reset(&buf);
    gquic_str_reset(&handshake_sec_derived_sec);
    gquic_str_reset(&ser_sec);
    return 0;
failure:

    gquic_tls_finished_msg_reset(&finished);
    gquic_str_reset(&buf);
    gquic_str_reset(&handshake_sec_derived_sec);
    gquic_str_reset(&ser_sec);
    return ret;
}

static int gquic_tls_handshake_server_state_read_cli_cert(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }
    
    // TODO
    
    return 0;
}

static int gquic_tls_handshake_server_state_read_cli_finished(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_tls_finished_msg_t *finished = NULL;
    u_int8_t msg_type = 0;
    if (ser_state == NULL) {
        return -1;
    }
    if (gquic_tls_conn_read_handshake(&msg_type, (void **) &finished, ser_state->conn) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        return -2;
    }
    if (msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        ret = -3;
        goto failure;
    }
    gquic_str_test_echo(&ser_state->cli_finished);
    gquic_str_test_echo(&finished->verify);
    if (gquic_str_cmp(&ser_state->cli_finished, &finished->verify) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_tls_half_conn_set_key(&ser_state->conn->in, GQUIC_ENC_LV_APP, ser_state->suite, &ser_state->traffic_sec) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&ser_state->conn->in, ser_state->suite, &ser_state->traffic_sec, 1) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }

    gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, finished);
    return 0;
failure:

    gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, finished);
    return ret;
}

static int gquic_tls_handshake_server_state_send_session_tickets(gquic_tls_handshake_server_state_t *const ser_state) {
    int ret = 0;
    gquic_tls_finished_msg_t cli_finished;
    gquic_str_t buf = { 0, NULL };
    if (ser_state == NULL) {
        return -1;
    }
    gquic_tls_finished_msg_init(&cli_finished);
    if (gquic_tls_cipher_suite_finished_hash(&ser_state->cli_finished,
                                             ser_state->suite,
                                             &ser_state->conn->in.traffic_sec,
                                             &ser_state->transport) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -2;
    }
    if (gquic_str_copy(&cli_finished.verify, &ser_state->cli_finished) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -3;
    }
    if (gquic_str_alloc(&buf, gquic_tls_finished_msg_size(&cli_finished)) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_tls_finished_msg_serialize(&cli_finished, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&ser_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(ser_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }

    return 0;
failure:

    return ret;
}

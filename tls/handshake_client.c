#include "tls/handshake_client.h"
#include "tls/common.h"
#include "tls/key_schedule.h"
#include "tls/alert.h"
#include "tls/hello_req_msg.h"
#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/new_sess_ticket_13_msg.h"
#include "tls/new_sess_ticket_msg.h"
#include "tls/cert_msg.h"
#include "tls/cert_13_msg.h"
#include "tls/cert_req_msg.h"
#include "tls/cert_req_13_msg.h"
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
#include <openssl/tls1.h>
#include <openssl/rand.h>

static int gquic_proto_copy(void *, const void *);

static int __cipher_suites[] = {
    TLS1_3_CK_AES_128_GCM_SHA256,
    TLS1_3_CK_CHACHA20_POLY1305_SHA256,
    TLS1_3_CK_AES_256_GCM_SHA384,

    TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
};

static u_int16_t __supported_sign_algos[] = {
    GQUIC_SIGALG_PSS_SHA256,
    GQUIC_SIGALG_ECDSA_P256_SHA256,
    GQUIC_SIGALG_ED25519,
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

static int gquic_tls_common_handshake_record_release(const u_int16_t, const u_int8_t, void *const);

static int gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_process_hello_retry_request(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_process_server_hello(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_establish_handshake_keys(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_params(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_cert(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_read_ser_finished(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_cli_cert(gquic_tls_handshake_client_state_t *const);
static int gquic_tls_client_handshake_state_send_cli_finished(gquic_tls_handshake_client_state_t *const);

int gquic_tls_handshake_client_state_init(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        return -1;
    }
    cli_state->conn = NULL;
    cli_state->s_hello = NULL;
    cli_state->c_hello = NULL;
    cli_state->early_sec = NULL;
    cli_state->binder_key = NULL;
    cli_state->cert_req = NULL;
    cli_state->using_psk = 0;
    cli_state->sent_dummy_ccs = 0;
    cli_state->suite = NULL;
    gquic_tls_ecdhe_params_init(&cli_state->ecdhe_params);
    gquic_tls_mac_init(&cli_state->transport);
    gquic_str_init(&cli_state->master_sec);
    gquic_str_init(&cli_state->traffic_sec);
    return 0;
}


int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t *const msg,
                                          gquic_tls_ecdhe_params_t *const params,
                                          const gquic_tls_conn_t *conn) {
    gquic_str_t *proto;
    size_t next_protos_len = 0;
    gquic_list_t supported_versions;
    u_int16_t client_hello_version;
    int ret = 0;
    size_t count;
    size_t i;

    if (msg == NULL || params == NULL || conn == NULL) {
        return -1;
    }
    if (gquic_list_head_init(&supported_versions) != 0) {
        return -2;
    }
    if (gquic_tls_client_hello_msg_init(msg) != 0) {
        ret = -3;
        goto failure;
    }
    if (gquic_tls_ecdhe_params_init(params) != 0) {
        ret = -4;
        goto failure;
    }

    if (GQUIC_STR_SIZE(&conn->cfg->ser_name) == 0 && !conn->cfg->insecure_skiy_verify) {
        ret = -5;
        goto failure;
    }
    GQUIC_LIST_FOREACH(proto, &conn->cfg->next_protos) {
        if (proto->size == 0 || proto->size > 255) {
            ret = -6;
            goto failure;
        }
        next_protos_len += proto->size;
    }
    if (next_protos_len > 0xffff) {
        ret = -7;
        goto failure;
    }
    if (gquic_tls_config_supported_versions(&supported_versions, conn->cfg, 1) != 0) {
        ret = -8;
        goto failure;
    }
    if (gquic_list_head_empty(&supported_versions)) {
        ret = -9;
        goto failure;
    }
    client_hello_version = *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_versions));
    if (client_hello_version > GQUIC_TLS_VERSION_12) {
        client_hello_version = GQUIC_TLS_VERSION_12;
    }

    msg->vers = client_hello_version;
    if (gquic_str_alloc(&msg->compression_methods, 1) != 0) {
        ret = -10;
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&msg->compression_methods) = 0;
    if (gquic_str_alloc(&msg->random, 32) != 0) {
        ret = -11;
        goto failure;
    }
    if (gquic_str_alloc(&msg->sess_id, 32) != 0) {
        ret = -12;
        goto failure;
    }
    msg->ocsp_stapling = 1;
    msg->scts = 1;
    if (gquic_str_copy(&msg->ser_name, &conn->cfg->ser_name) != 0) {
        ret = -13;
        goto failure;
    }
    if (gquic_tls_config_curve_preferences(&msg->supported_curves) != 0) {
        ret = -14;
        goto failure;
    }
    if (gquic_str_alloc(&msg->supported_points, 1) != 0) {
        ret = -15;
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&msg->supported_points) = 0;
    msg->next_proto_neg = !gquic_list_head_empty(&conn->cfg->next_protos);
    msg->secure_regegotiation_supported = 1;
    if (gquic_list_copy(&msg->alpn_protos, &conn->cfg->next_protos, gquic_proto_copy) != 0) {
        ret = -16;
        goto failure;
    }
    if (gquic_list_copy(&msg->supported_versions, &supported_versions, NULL) != 0) {
        ret = -17;
        goto failure;
    }
    count = sizeof(__cipher_suites) / sizeof(int);
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = gquic_list_alloc(sizeof(u_int16_t));
        if (cipher_suite == NULL) {
            ret = -18;
            goto failure;
        }
        *cipher_suite = 0xFFFF & __cipher_suites[i];
        if (gquic_list_insert_before(&msg->cipher_suites, cipher_suite) != 0) {
            ret = -19;
            goto failure;
        }
    }
    RAND_bytes(GQUIC_STR_VAL(&msg->random), GQUIC_STR_SIZE(&msg->random));
    RAND_bytes(GQUIC_STR_VAL(&msg->sess_id), GQUIC_STR_SIZE(&msg->sess_id));
    if (msg->vers >= GQUIC_TLS_VERSION_12) {
        count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = gquic_list_alloc(sizeof(u_int16_t));
            if (sigalg == NULL) {
                ret = -20;
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (gquic_list_insert_before(&msg->supported_sign_algos, sigalg) != 0) {
                ret = -21;
                goto failure;
            }
        }
    }
    if (gquic_tls_handshake_client_hello_edch_params_init(params, msg, conn->cfg) != 0) {
        ret = -22;
        goto failure;
    }

    while (!gquic_list_head_empty(&supported_versions)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_versions)));
    }
    return 0;
failure:
    while (!gquic_list_head_empty(&supported_versions)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_versions)));
    }
    gquic_tls_client_hello_msg_reset(msg);
    return ret;
}

static int gquic_proto_copy(void *proto, const void *ref_proto) {
    if (proto == NULL || ref_proto == NULL) {
        return -1;
    }
    return gquic_str_copy(proto, ref_proto);
}

static int gquic_tls_handshake_client_hello_edch_params_init(gquic_tls_ecdhe_params_t *const params, gquic_tls_client_hello_msg_t *const msg, const gquic_tls_config_t *const cfg) {
    gquic_tls_key_share_t *ks = NULL;
    int ret = 0;
    if (params == NULL || msg == NULL) {
        return -1;
    }
    if (*((u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_versions))) == GQUIC_TLS_VERSION_13) {
        if (gquic_tls_ecdhe_params_generate(params, GQUIC_TLS_CURVE_X25519) != 0) {
            ret = -2;
            goto failure;
        }
        gquic_tls_key_share_t *ks = gquic_list_alloc(sizeof(gquic_tls_key_share_t));
        if (ks == NULL) {
            ret = -3;
            goto failure;
        }
        gquic_list_head_init(&GQUIC_LIST_META(ks));
        ks->group = GQUIC_TLS_CURVE_X25519;
        gquic_str_init(&ks->data);
        if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(params, &ks->data) != 0) {
            ret = -4;
            goto failure;
        }
        if (gquic_list_insert_before(&msg->key_shares, ks) != 0) {
            ret = -5;
            goto failure;
        }
        if (cfg->extensions != NULL && cfg->extensions(&msg->extensions, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) != 0) {
            ret = -6;
            goto failure;
        }
    }
    return 0;
failure:
    gquic_tls_ecdhe_params_release(params);
    if (ks != NULL) {
        gquic_list_release(ks);
    }
    return ret;
}

int gquic_tls_client_handshake(gquic_tls_conn_t *const conn) {
    gquic_tls_handshake_client_state_t client_handshake_state;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t cache_key = { 0, NULL };
    gquic_tls_client_sess_state_t *sess = NULL;
    gquic_str_t early_sec = { 0, NULL };
    gquic_str_t binder_key = { 0, NULL };
    size_t _ = 0;
    int ret = 0;
    u_int8_t received_record_type = 0;
    if (conn == NULL) {
        return -1;
    }
    if (conn->cfg == NULL) {
        gquic_tls_config_default(&conn->cfg);
    }
    if (gquic_tls_handshake_client_state_init(&client_handshake_state) != 0) {
        return -2;
    }
    if ((client_handshake_state.c_hello = malloc(sizeof(gquic_tls_client_hello_msg_t))) == NULL) {
        return -3;
    }
    if (gquic_tls_conn_set_alt_record(conn) != 0) {
        return -4;
    }
    if (gquic_tls_client_hello_msg_init(client_handshake_state.c_hello) != 0) {
        return -5;
    }
    if (gquic_tls_ecdhe_params_init(&client_handshake_state.ecdhe_params) != 0) {
        return -6;
    }
    if (gquic_tls_handshake_client_hello_init(client_handshake_state.c_hello, &client_handshake_state.ecdhe_params, conn) != 0) {
        return -7;
    }
    if (gquic_tls_conn_load_session(&cache_key, &sess, &early_sec, &binder_key, conn, client_handshake_state.c_hello) != 0) {
        return -8;
    }
    if (gquic_tls_client_hello_msg_serialize(client_handshake_state.c_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) != 0) {
        return -9;
    }
    if (gquic_tls_conn_write_record(&_, conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        ret = -10;
        goto failure;
    }
    if ((gquic_tls_conn_read_handshake(&received_record_type, (void **) &client_handshake_state.s_hello, conn) != 0)
        && received_record_type == GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
       ret = -11;
       goto failure;
    }

    if (conn->ver != GQUIC_TLS_VERSION_13) {
        // unsupport < version 13
        ret = -12;
        goto failure;
    }
    client_handshake_state.conn = conn;
    client_handshake_state.sess = sess;
    client_handshake_state.early_sec = &early_sec;
    client_handshake_state.binder_key = &binder_key;
    if (gquic_tls_client_handshake_state_handshake(&client_handshake_state) != 0) {
        ret = -13;
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&cache_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&binder_key);
    gquic_tls_handshake_client_state_release(&client_handshake_state);
    return 0;
failure:
    gquic_str_reset(&buf);
    gquic_str_reset(&cache_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&binder_key);
    gquic_tls_handshake_client_state_release(&client_handshake_state);
    return ret;
}

static int gquic_tls_common_handshake_record_release(const u_int16_t ver, const u_int8_t record_type, void *const msg) {
    if (msg == NULL) {
        return -1;
    }
    switch (record_type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ:
        gquic_tls_hello_req_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        gquic_tls_client_hello_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        gquic_tls_server_hello_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        if (ver == GQUIC_TLS_VERSION_13) {
            gquic_tls_new_sess_ticket_13_msg_reset(msg);
        }
        else {
            gquic_tls_new_sess_ticket_msg_reset(msg);
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
        if (ver == GQUIC_TLS_VERSION_13) {
            gquic_tls_cert_13_msg_reset(msg);
        }
        else {
            gquic_tls_cert_msg_reset(msg);
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
        if (ver == GQUIC_TLS_VERSION_13) {
            gquic_tls_cert_req_13_msg_reset(msg);
        }
        else {
            gquic_tls_cert_req_msg_reset(msg);
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS:
        gquic_tls_cert_status_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE:
        gquic_tls_server_key_exchange_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE:
        gquic_tls_server_hello_done_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE:
        gquic_tls_client_key_exchange_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        gquic_tls_cert_verify_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO:
        gquic_tls_next_proto_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        gquic_tls_finished_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        gquic_tls_encrypt_ext_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA:
        gquic_tls_end_of_early_data_msg_reset(msg);
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE:
        gquic_tls_key_update_msg_reset(msg);
        break;
    }
    free(msg);
    return 0;
}

int gquic_tls_client_handshake_state_handshake(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->conn->handshakes > 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_PROTOCOL_VERSION);
        return -2;
    }
    // note: unsupported RSA KA
    if (cli_state->ecdhe_params.self == NULL
        || (!gquic_list_head_empty(&cli_state->c_hello->key_shares)
            && gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->key_shares)) == gquic_list_prev(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->key_shares)))) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -3;
    }
    if (gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(cli_state) != 0) {
        return -4;
    }
    if (gquic_str_cmp(&cli_state->s_hello->random, gquic_tls_hello_retry_request_random()) == 0) {
        if (gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state) != 0) {
            return -5;
        }
        if (gquic_tls_client_handshake_state_process_hello_retry_request(cli_state) != 0) {
            return -6;
        }
    }

    cli_state->conn->buffering = 1;
    if (gquic_tls_client_handshake_state_process_server_hello(cli_state) != 0) {
        return -7;
    }
    if (gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state) != 0) {
        return -8;
    }
    if (gquic_tls_client_handshake_state_establish_handshake_keys(cli_state) != 0) {
        return -9;
    }
    if (gquic_tls_client_handshake_state_read_ser_params(cli_state) != 0) {
        return -10;
    }
    if (gquic_tls_client_handshake_state_read_ser_cert(cli_state) != 0) {
        return -11;
    }
    if (gquic_tls_client_handshake_state_read_ser_finished(cli_state) != 0) {
        return -12;
    }
    if (gquic_tls_client_handshake_state_send_cli_cert(cli_state) != 0) {
        return -13;
    }
    if (gquic_tls_client_handshake_state_send_cli_finished(cli_state) != 0) {
        return -14;
    }
    cli_state->conn->handshake_status = 1;
    return 0;
}

static int gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(gquic_tls_handshake_client_state_t *const cli_state) {
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->s_hello->supported_version == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_MISSING_EXTENSION);
        return -2;
    }
    if (cli_state->s_hello->supported_version != GQUIC_TLS_VERSION_13) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -3;
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
        return -4;
    }
    if (gquic_str_cmp(&cli_state->c_hello->sess_id, &cli_state->s_hello->sess_id) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -5;
    }
    if (cli_state->s_hello->compression_method != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -6;
    }
    if (gquic_tls_choose_cipher_suite(&cipher_suite, &cli_state->c_hello->cipher_suites, cli_state->s_hello->cipher_suite) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -7;
    }
    if (cipher_suite == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -8;
    }
    if (cli_state->suite != NULL && cli_state->suite != cipher_suite) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -9;
    }
    cli_state->suite = cipher_suite;
    cli_state->conn->cipher_suite = cipher_suite->id;

    return 0;
}

int gquic_tls_handshake_client_state_release(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        return -1;
    }
    // TODO
    return 0;
}

static int gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(gquic_tls_handshake_client_state_t *const cli_state) {
    u_int8_t record_payload[] = { 0x01 };
    gquic_str_t record = { sizeof(record_payload), record_payload };
    size_t _;
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->sent_dummy_ccs) {
        return 0;
    }
    cli_state->sent_dummy_ccs = 1;
    if (gquic_tls_conn_write_record(&_, cli_state->conn, GQUIC_TLS_RECORD_TYPE_CHANGE_CIPHER_SEPC, &record) != 0) {
        return -2;
    }
    return 0;
}

static int gquic_tls_client_handshake_state_process_hello_retry_request(gquic_tls_handshake_client_state_t *const cli_state) {
    u_int16_t curve_id = 0;
    int supported_curve = 0;
    u_int16_t *c_curve_id = NULL;
    gquic_tls_key_share_t *key_share = NULL;
    int ret = 0;
    gquic_str_t buf = { 0, NULL };
    size_t _;
    u_int8_t handshake_type = 0;
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->s_hello->ser_share.group != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        return -2;
    }
    if ((curve_id = cli_state->s_hello->selected_group) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_MISSING_EXTENSION);
        return -3;
    }
    GQUIC_LIST_FOREACH(c_curve_id, &cli_state->c_hello->supported_curves) {
        if (*c_curve_id == curve_id) {
            supported_curve = 1;
            break;
        }
    }
    if (supported_curve == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -4;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(&cli_state->ecdhe_params) == curve_id) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -5;
    }
    if (gquic_tls_ecdhe_params_release(&cli_state->ecdhe_params) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -6;
    }
    if (gquic_tls_ecdhe_params_init(&cli_state->ecdhe_params) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -7;
    }
    if (gquic_tls_ecdhe_params_generate(&cli_state->ecdhe_params, curve_id) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -8;
    }
    if ((key_share = gquic_list_alloc(sizeof(gquic_tls_key_share_t))) == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -9;
        goto failure;
    }
    key_share->group = curve_id;
    gquic_str_init(&key_share->data);
    if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&cli_state->ecdhe_params, &key_share->data) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -10;
        goto failure;
    }
    gquic_list_insert_before(&cli_state->c_hello->key_shares, key_share);
    if (gquic_str_copy(&cli_state->c_hello->cookie, &cli_state->s_hello->cookie) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -11;
    }
    key_share = NULL;

    if (!gquic_list_head_empty(&cli_state->c_hello->psk_identities)) {
        const gquic_tls_cipher_suite_t *psk_suite = NULL;
        if (gquic_tls_get_cipher_suite(&psk_suite, cli_state->sess->cipher_suite) != 0 || psk_suite == NULL) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            return -12;
        }
        if (psk_suite->hash == cli_state->suite->hash) {
            // TODO: psk
        }
        else {
            // TODO: psk
        }
    }

    if (gquic_str_alloc(&buf, gquic_tls_client_hello_msg_size(cli_state->c_hello)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -13;
    }
    if (gquic_tls_client_hello_msg_serialize(cli_state->c_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&_, cli_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -15;
        goto failure;
    }
    if (cli_state->s_hello != NULL) {
        gquic_tls_server_hello_msg_reset(cli_state->s_hello);
        free(cli_state->s_hello);
        cli_state->s_hello = NULL;
    }
    if (gquic_tls_conn_read_handshake(&handshake_type, (void **) &cli_state->s_hello, cli_state->conn) != 0
        || handshake_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -17;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(cli_state) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -18;
        goto failure;
    }

    gquic_str_reset(&buf);
    return 0;
failure:
    if (key_share != NULL) {
        if (GQUIC_STR_SIZE(&key_share->data) != 0) {
            gquic_str_reset(&key_share->data);
        }
        gquic_list_release(key_share);
    }
    gquic_str_reset(&buf);
    return ret;
}

static int gquic_tls_client_handshake_state_process_server_hello(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        return -1;
    }

    if (gquic_str_cmp(&cli_state->s_hello->random, gquic_tls_hello_retry_request_random()) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        return -2;
    }
    if (GQUIC_STR_SIZE(&cli_state->s_hello->cookie) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        return -3;
    }
    if (cli_state->s_hello->selected_group != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        return -4;
    }
    if (cli_state->s_hello->ser_share.group == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -5;
    }
    if (cli_state->s_hello->ser_share.group != GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(&cli_state->ecdhe_params)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -6;
    }

    if (!cli_state->s_hello->selected_identity_persent) {
        return 0;
    }
    
    // TODO: psk

    return 0;
}

static int gquic_tls_client_handshake_state_establish_handshake_keys(gquic_tls_handshake_client_state_t *const cli_state) {
    int ret = 0;
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
        ret = -1;
        goto failure;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&cli_state->ecdhe_params, &shared_key, &cli_state->s_hello->ser_share.data) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -2;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&shared_key) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -3;
        goto failure;
    }
    if (gquic_str_copy(&early_sec, cli_state->early_sec) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -4;
        goto failure;
    }
    if (!cli_state->using_psk) {
        gquic_str_reset(&early_sec);
        gquic_tls_cipher_suite_extract(&early_sec, cli_state->suite, NULL, NULL);
    }
    if (gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, cli_state->suite, NULL, &early_sec, &derived_label) != 0) {
        ret = -5;
        goto failure;
    }
    if (gquic_tls_cipher_suite_extract(&handshake_sec, cli_state->suite, &shared_key, &early_sec_derived_sec) != 0) {
        ret = -6;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&cli_sec, cli_state->suite, &cli_state->transport, &handshake_sec, &cli_handshake_traffic_label) != 0) {
        ret = -7;
        goto failure;
    }
    if (cli_state->conn->out.set_key(cli_state->conn->out.set_key_self, GQUIC_ENC_LV_HANDSHAKE, cli_state->suite, &cli_sec) != 0) {
        ret = -8;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->out, cli_state->suite, &cli_sec, 0) != 0) {
        ret = -9;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&ser_sec, cli_state->suite, &cli_state->transport, &handshake_sec, &ser_handshake_traffic_label) != 0) {
        ret = -10;
        goto failure;
    }
    if (cli_state->conn->in.set_key(cli_state->conn->in.set_key_self, GQUIC_ENC_LV_HANDSHAKE, cli_state->suite, &ser_sec) != 0) {
        ret = -11;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->in, cli_state->suite, &ser_sec, 1) != 0) {
        ret = -12;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&handshake_sec_derived_sec, cli_state->suite, NULL, &handshake_sec, &derived_label) != 0) {
        ret = -13;
        goto failure;
    }
    if (gquic_tls_cipher_suite_extract(&cli_state->master_sec, cli_state->suite, NULL, &handshake_sec_derived_sec) != 0) {
        ret = -14;
        goto failure;
    }

    gquic_str_reset(&shared_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&handshake_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&handshake_sec_derived_sec);
    return 0;
failure:
    gquic_str_reset(&shared_key);
    gquic_str_reset(&early_sec);
    gquic_str_reset(&handshake_sec);
    gquic_str_reset(&cli_sec);
    gquic_str_reset(&ser_sec);
    gquic_str_reset(&early_sec_derived_sec);
    gquic_str_reset(&handshake_sec_derived_sec);
    return ret;
}

static int gquic_tls_client_handshake_state_read_ser_params(gquic_tls_handshake_client_state_t *const cli_state) {

}

static int gquic_tls_client_handshake_state_read_ser_cert(gquic_tls_handshake_client_state_t *const cli_state) {

}

static int gquic_tls_client_handshake_state_read_ser_finished(gquic_tls_handshake_client_state_t *const cli_state) {

}

static int gquic_tls_client_handshake_state_send_cli_cert(gquic_tls_handshake_client_state_t *const cli_state) {

}

static int gquic_tls_client_handshake_state_send_cli_finished(gquic_tls_handshake_client_state_t *const cli_state) {

}


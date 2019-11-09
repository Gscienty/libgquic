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
#include "tls/prf.h"
#include "tls/auth.h"
#include "util/time.h"
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

static int mutual_protocol(const gquic_str_t *const, const gquic_list_t *const);

static int copy_peer_cert(void *const, const void *const);
static int copy_verify(void *const, const void *const);

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
    if ((ret = gquic_tls_handshake_client_hello_init(client_handshake_state.c_hello, &client_handshake_state.ecdhe_params, conn)) != 0) {
        return -7 + ret * 100;
    }
    if (gquic_tls_conn_load_session(&cache_key, &sess, &early_sec, &binder_key, conn, client_handshake_state.c_hello) != 0) {
        return -8;
    }
    if (gquic_str_alloc(&buf, gquic_tls_client_hello_msg_size(client_handshake_state.c_hello)) != 0) {
        return -9;
    }
    if ((ret = gquic_tls_client_hello_msg_serialize(client_handshake_state.c_hello, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf))) < 0) {
        return -10 + ret * 100;
    }
    if (gquic_tls_conn_write_record(&_, conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        ret = -11;
        goto failure;
    }
    if ((gquic_tls_conn_read_handshake(&received_record_type, (void **) &client_handshake_state.s_hello, conn) != 0)
        && received_record_type == GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO) {
       ret = -12;
       goto failure;
    }

    if (conn->ver != GQUIC_TLS_VERSION_13) {
        // unsupport < version 13
        ret = -13;
        goto failure;
    }
    client_handshake_state.conn = conn;
    client_handshake_state.sess = sess;
    client_handshake_state.early_sec = &early_sec;
    client_handshake_state.binder_key = &binder_key;
    if (gquic_tls_client_handshake_state_handshake(&client_handshake_state) != 0) {
        ret = -14;
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
    int ret = 0;
    gquic_str_t buf = { 0, NULL };
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
    if (cli_state->suite->mac(&cli_state->transport, 0, NULL) != 0) {
        return -5;
    }
    if (gquic_str_alloc(&buf, gquic_tls_client_hello_msg_size(cli_state->c_hello)) != 0) {
        return -6;
    }
    if (gquic_tls_client_hello_msg_serialize(cli_state->c_hello, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
        ret = -7;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        ret = -8;
        goto failure;
    }
    if (gquic_str_cmp(&cli_state->s_hello->random, gquic_tls_hello_retry_request_random()) == 0) {
        if (gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state) != 0) {
            ret = -9;
            goto failure;
        }
        if (gquic_tls_client_handshake_state_process_hello_retry_request(cli_state) != 0) {
            ret = -10;
            goto failure;
        }
    }
    if (gquic_str_reset(&buf) != 0) {
        ret = -12;
        goto failure;
    }
    if (gquic_str_init(&buf) != 0) {
        return -13;
    }
    if (gquic_str_alloc(&buf, gquic_tls_server_hello_msg_size(cli_state->s_hello)) != 0) {
        return -14;
    }
    if (gquic_tls_server_hello_msg_serialize(cli_state->s_hello, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
        ret = -15;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        ret = -16;
        goto failure;
    }

    cli_state->conn->buffering = 1;
    if (gquic_tls_client_handshake_state_process_server_hello(cli_state) != 0) {
        ret = -17;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_send_dummy_change_cipher_spec(cli_state) != 0) {
        ret = -18;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_establish_handshake_keys(cli_state) != 0) {
        ret = -19;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_read_ser_params(cli_state) != 0) {
        ret = -20;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_read_ser_cert(cli_state) != 0) {
        ret = -21;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_read_ser_finished(cli_state) != 0) {
        ret = -22;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_send_cli_cert(cli_state) != 0) {
        ret = -23;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_send_cli_finished(cli_state) != 0) {
        ret = -24;
        goto failure;
    }
    cli_state->conn->handshake_status = 1;
    gquic_str_reset(&buf);
    return 0;
failure:
    gquic_str_reset(&buf);
    return ret;
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
    gquic_str_t sh_buf = { 0, NULL };
    gquic_str_t ch_buf = { 0, NULL };
    gquic_str_t ch_hash = { 0, NULL };
    size_t _;
    u_int8_t handshake_type = 0;
    if (cli_state == NULL) {
        return -1;
    }
    if (gquic_tls_mac_md_sum(&ch_hash, &cli_state->transport) <= 0) {
        return -2;
    }
    const u_int8_t msg_hash_header_cnt[] = { GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH, 0, 0, (u_int8_t) GQUIC_STR_SIZE(&ch_hash) };
    const gquic_str_t msg_hash_header = { 4, (void *) msg_hash_header_cnt };
    gquic_tls_mac_md_update(&cli_state->transport, &msg_hash_header);
    gquic_tls_mac_md_update(&cli_state->transport, &ch_hash);
    if (gquic_str_alloc(&sh_buf, gquic_tls_server_hello_msg_size(cli_state->s_hello)) != 0) {
        return -3;
    }
    if (gquic_tls_server_hello_msg_serialize(cli_state->s_hello, &sh_buf, GQUIC_STR_SIZE(&sh_buf)) < 0) {
        return -4;
    }
    gquic_tls_mac_md_update(&cli_state->transport, &sh_buf);

    if (cli_state->s_hello->ser_share.group != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        return -5;
    }
    if ((curve_id = cli_state->s_hello->selected_group) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_MISSING_EXTENSION);
        return -6;
    }
    GQUIC_LIST_FOREACH(c_curve_id, &cli_state->c_hello->supported_curves) {
        if (*c_curve_id == curve_id) {
            supported_curve = 1;
            break;
        }
    }
    if (supported_curve == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -7;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_CURVE_ID(&cli_state->ecdhe_params) == curve_id) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -8;
    }
    if (gquic_tls_ecdhe_params_release(&cli_state->ecdhe_params) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -9;
    }
    if (gquic_tls_ecdhe_params_init(&cli_state->ecdhe_params) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -10;
    }
    if (gquic_tls_ecdhe_params_generate(&cli_state->ecdhe_params, curve_id) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -11;
    }
    if ((key_share = gquic_list_alloc(sizeof(gquic_tls_key_share_t))) == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    key_share->group = curve_id;
    gquic_str_init(&key_share->data);
    if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&cli_state->ecdhe_params, &key_share->data) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    gquic_list_insert_before(&cli_state->c_hello->key_shares, key_share);
    if (gquic_str_copy(&cli_state->c_hello->cookie, &cli_state->s_hello->cookie) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -14;
    }
    key_share = NULL;

    if (gquic_str_alloc(&ch_buf, gquic_tls_client_hello_msg_size(cli_state->c_hello)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -15;
    }
    if (gquic_tls_client_hello_msg_serialize(cli_state->c_hello, GQUIC_STR_VAL(&ch_buf), GQUIC_STR_SIZE(&ch_buf)) < 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -16;
        goto failure;
    }
    if (!gquic_list_head_empty(&cli_state->c_hello->psk_identities)) {
        const gquic_tls_cipher_suite_t *psk_suite = NULL;
        if (gquic_tls_get_cipher_suite(&psk_suite, cli_state->sess->cipher_suite) != 0 || psk_suite == NULL) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            ret = -17;
            goto failure;
        }
        if (psk_suite->hash == cli_state->suite->hash) {
            int64_t ticket_age = 0;
            gquic_time_since_milli(&ticket_age, &cli_state->sess->received_at);
            gquic_tls_psk_identity_t *psk_identity = gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->psk_identities));
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
            if (gquic_tls_mac_md_sum(&binder, &transport) != 0) {
                ret = -18;
                gquic_tls_mac_release(&transport);
                goto failure;
            }
            gquic_tls_mac_release(&transport);

            size_t origin_psk_binders_count = 0;
            void *_;
            GQUIC_LIST_FOREACH(_, &cli_state->c_hello->psk_binders) origin_psk_binders_count++;
            if (origin_psk_binders_count != 0) {
                ret = -19;
                gquic_str_reset(&binder);
                goto failure;
            }
            gquic_str_t *psk_binder = gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->psk_binders));
            if (GQUIC_STR_SIZE(psk_binder) != GQUIC_STR_SIZE(&binder)) {
                ret = -20;
                gquic_str_reset(&binder);
                goto failure;
            }
            gquic_str_reset(psk_binder);
            psk_binder->val = GQUIC_STR_VAL(&binder);
        }
        else {
            while (!gquic_list_head_empty(&cli_state->c_hello->psk_identities)) {
                gquic_tls_psk_identity_t *removed = gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->psk_identities));
                gquic_str_reset(&removed->label);
                gquic_list_release(removed);
            }
            while (!gquic_list_head_empty(&cli_state->c_hello->psk_binders)) {
                gquic_str_t *binder = gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->c_hello->psk_binders));
                gquic_str_reset(binder);
                gquic_list_release(binder);
            }
        }
    }

    if (gquic_tls_conn_write_record(&_, cli_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &ch_buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -21;
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
        ret = -22;
        goto failure;
    }
    if (gquic_tls_client_handshake_state_check_ser_hello_or_hello_retry_req(cli_state) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -23;
        goto failure;
    }

    gquic_str_reset(&sh_buf);
    gquic_str_reset(&ch_buf);
    gquic_str_reset(&ch_hash);
    return 0;
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
    return ret;
}

static int gquic_tls_client_handshake_state_process_server_hello(gquic_tls_handshake_client_state_t *const cli_state) {
    const gquic_tls_cipher_suite_t *psk_suite = NULL;
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
    u_int16_t cli_psk_identities_count = ({
                                          u_int16_t ret = 0;
                                          void *_;
                                          GQUIC_LIST_FOREACH(_, &cli_state->c_hello->psk_identities) ret++;
                                          ret;
                                          });
    if (cli_state->s_hello->selected_identity >= cli_psk_identities_count) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -7;
    }
    if (cli_psk_identities_count != 1 || cli_state->sess == NULL) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -8;
    }
    if (gquic_tls_get_cipher_suite(&psk_suite, cli_state->sess->cipher_suite) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        return -9;
    }
    if (psk_suite->mac != cli_state->suite->mac) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        return -10;
    }
    cli_state->using_psk = 1;
    cli_state->conn->did_resume = 1;
    gquic_list_copy(&cli_state->conn->peer_certs, &cli_state->sess->ser_certs, copy_peer_cert);
    gquic_list_copy(&cli_state->conn->verified_chains, &cli_state->sess->verified_chains, copy_verify);
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
    gquic_tls_encrypt_ext_msg_t *msg = NULL;
    u_int8_t msg_type = 0;
    gquic_str_t buf = { 0, NULL };
    int ret = 0;
    if (cli_state == NULL) {
        return -1;
    }
    if (gquic_tls_conn_read_handshake(&msg_type, (void **) &msg, cli_state->conn) != 0) {
        return -2;
    }
    if (msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        ret = -3;
        goto failure;
    }
    if (cli_state->conn->cfg->received_extensions != NULL
        && cli_state->conn->cfg->received_extensions(GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS, &msg->addition_exts) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_str_alloc(&buf, gquic_tls_encrypt_ext_msg_size(msg)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_encrypt_ext_msg_serialize(msg, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (GQUIC_STR_SIZE(&msg->alpn_proto) != 0 && gquic_list_head_empty(&cli_state->c_hello->alpn_protos)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNSUPPORTED_EXTENSION);
        ret = -8;
        goto failure;
    }
    if (cli_state->conn->cfg->enforce_next_proto_selection) {
        if (GQUIC_STR_SIZE(&msg->alpn_proto) == 0) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
            ret = -9;
            goto failure;
        }
        if (mutual_protocol(&msg->alpn_proto, &cli_state->conn->cfg->next_protos) != 0) {
            gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_NO_APP_PROTOCOL);
            ret = -10;
            goto failure;
        }
    }
    if (gquic_str_copy(&cli_state->conn->cli_proto, &msg->alpn_proto) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }

    gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, msg);
    gquic_str_reset(&buf);
    return 0;
failure:
    gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, msg);
    gquic_str_reset(&buf);
    return ret;
}

static int gquic_tls_client_handshake_state_read_ser_cert(gquic_tls_handshake_client_state_t *const cli_state) {
    static const gquic_str_t ser_sign_cnt = { 38, "GQUIC-TLSv1.3, server SignatureContent" };
    int ret = 0;
    void *msg = NULL;
    u_int8_t msg_type = 0;
    gquic_str_t buf = { 0, NULL };
    gquic_str_t sign = { 0, NULL };
    gquic_tls_cert_13_msg_t *cert_msg = NULL;
    gquic_tls_cert_verify_msg_t *verify_msg = NULL;
    gquic_list_t supported_sigalgs;
    const EVP_MD *sig_hash = NULL;
    EVP_PKEY *pubkey = NULL;
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->using_psk) {
        return 0;
    }
    {
        gquic_list_head_init(&supported_sigalgs);
        size_t count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
        size_t i;
        for (i = 0; i < count; i++) {
            u_int16_t *sigalg = gquic_list_alloc(sizeof(u_int16_t));
            if (sigalg == NULL) {
                ret = -2;
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (gquic_list_insert_before(&supported_sigalgs, sigalg) != 0) {
                ret = -3;
                goto failure;
            }
        }
    }

    if (gquic_tls_conn_read_handshake(&msg_type, &msg, cli_state->conn) != 0) {
        return -4;
    }
    if (msg_type == GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ) {
        if (gquic_str_alloc(&buf, gquic_tls_cert_req_13_msg_size(msg)) != 0) {
            return -5;
        }
        if (gquic_tls_cert_req_13_msg_serialize(msg, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
            ret = -6;
            goto failure;
        }
        if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
            ret = -7;
            gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, msg);
            goto failure;
        }
        cli_state->cert_req = msg;
        if (gquic_tls_conn_read_handshake(&msg_type, &msg, cli_state->conn) != 0) {
            ret = -8;
            goto failure;
        }
    }
    if (msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        ret = -9;
        goto failure;
    }
    cert_msg = msg;
    if (gquic_list_head_empty(&cert_msg->cert.certs)) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        ret = -10;
        goto failure;
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_str_alloc(&buf, gquic_tls_cert_13_msg_size(cert_msg)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_cert_13_msg_serialize(cert_msg, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -13;
        goto failure;
    }
    gquic_str_reset(&buf);
    gquic_str_init(&buf);
    if (gquic_tls_conn_read_handshake(&msg_type, (void **) &verify_msg, cli_state->conn) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -14;
        goto failure;
    }
    if (msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        ret = -15;
        goto failure;
    }
    if (gquic_tls_is_supported_sigalg(verify_msg->sign_algo, &supported_sigalgs) == 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -16;
        goto failure;
    }
    if (gquic_tls_hash_from_sigalg(&sig_hash, verify_msg->sign_algo) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -17;
        goto failure;
    }
    const u_int8_t sig_type = gquic_tls_sig_from_sigalg(verify_msg->sign_algo);
    if (sig_type == 0xff) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -18;
        goto failure;
    }
    if (sig_type == GQUIC_SIG_PKCS1V15 || sig_hash == EVP_sha1()) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -19;
        goto failure;
    }
    if (gquic_tls_signed_msg(&sign, sig_hash, &ser_sign_cnt, &cli_state->transport) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_ILLEGAL_PARAMS);
        ret = -20;
        goto failure;
    }
    if (gquic_tls_sig_pubkey(&pubkey, sig_type, gquic_list_next(GQUIC_LIST_PAYLOAD(&cli_state->conn->peer_certs))) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        ret = -21;
        goto failure;
    }
    if (gquic_tls_verify_handshake_sign(sig_hash, pubkey, &sign, &verify_msg->sign) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECRYPT_ERROR);
        ret = -22;
        goto failure;
    }

    if (gquic_str_alloc(&buf, gquic_tls_cert_verify_msg_size(verify_msg)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -23;
        goto failure;
    }
    if (gquic_tls_cert_verify_msg_serialize(verify_msg, &buf, GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -24;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -25;
        goto failure;
    }

    gquic_str_reset(&buf);
    gquic_str_reset(&sign);
    if (cert_msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT, cert_msg);
    }
    if (verify_msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY, verify_msg);
    }
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    while (!gquic_list_head_empty(&supported_sigalgs)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_sigalgs)));
    }
    return 0;
failure:
    gquic_str_reset(&buf);
    gquic_str_reset(&sign);
    if (cert_msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT, cert_msg);
    }
    if (verify_msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY, verify_msg);
    }
    if (pubkey != NULL) {
        EVP_PKEY_free(pubkey);
    }
    while (!gquic_list_head_empty(&supported_sigalgs)) {
        gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_sigalgs)));
    }
    return ret;
}

static int gquic_tls_client_handshake_state_read_ser_finished(gquic_tls_handshake_client_state_t *const cli_state) {
    int ret = 0;
    static const gquic_str_t cli_app_traffic_label = { 12, "c ap traffic" };
    static const gquic_str_t ser_app_traffic_label = { 12, "s ap traffic" };
    gquic_tls_finished_msg_t *msg = NULL;
    gquic_str_t expected_mac = { 0, NULL };
    gquic_str_t buf = { 0, NULL };
    gquic_str_t ser_sec = { 0, NULL };
    u_int8_t msg_type = 0;
    if (cli_state == NULL) {
        return -1;
    }
    if (gquic_tls_conn_read_handshake(&msg_type, (void **) &msg, cli_state->conn) != 0 && msg_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
        return -2;
    }
    if (gquic_tls_cipher_suite_finished_hash(&expected_mac, cli_state->suite, &cli_state->conn->in.traffic_sec, &cli_state->transport) != 0) {
        return -3;
    }
    if (gquic_str_cmp(&expected_mac, &msg->verify) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_DECODE_ERROR);
        ret = -4;
        goto failure;
    }
    if (gquic_str_alloc(&buf, gquic_tls_finished_msg_size(msg)) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -5;
        goto failure;
    }
    if (gquic_tls_finished_msg_serialize(msg, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -6;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -7;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&cli_state->traffic_sec,
                                             cli_state->suite,
                                             &cli_state->transport,
                                             &cli_state->master_sec,
                                             &cli_app_traffic_label) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -8;
        goto failure;
    }
    if (gquic_tls_cipher_suite_derive_secret(&ser_sec,
                                             cli_state->suite,
                                             &cli_state->transport,
                                             &cli_state->master_sec,
                                             &ser_app_traffic_label) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -9;
        goto failure;
    }
    if (gquic_tls_half_conn_set_key(&cli_state->conn->in, GQUIC_ENC_LV_APP, cli_state->suite, &ser_sec) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -10;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->in, cli_state->suite, &ser_sec, 1) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -11;
        goto failure;
    }
    if (gquic_tls_cipher_suite_export_keying_material(&cli_state->conn->ekm,
                                                      cli_state->suite,
                                                      &cli_state->master_sec,
                                                      &cli_state->transport) != 0) {
        gquic_tls_conn_send_alert(cli_state->conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
        ret = -12;
        goto failure;
    }

    if (msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, msg);
    }
    gquic_str_reset(&expected_mac);
    gquic_str_reset(&buf);
    gquic_str_reset(&ser_sec);
    return 0;
failure:
    if (msg != NULL) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, msg_type, msg);
    }
    gquic_str_reset(&expected_mac);
    gquic_str_reset(&buf);
    gquic_str_reset(&ser_sec);
    return ret;
}

static int gquic_tls_client_handshake_state_send_cli_cert(gquic_tls_handshake_client_state_t *const cli_state) {
    if (cli_state == NULL) {
        return -1;
    }
    if (cli_state->cert_req == NULL) {
        return 0;
    }

    // TODO

    return 0;
}

static int gquic_tls_client_handshake_state_send_cli_finished(gquic_tls_handshake_client_state_t *const cli_state) {
    size_t len = 0;
    int ret = 0;
    gquic_tls_finished_msg_t finished;
    gquic_str_t buf = { 0, NULL };
    static const gquic_str_t resumption_label = { 10, "res master" };
    if (cli_state == NULL) {
        return -1;
    }
    gquic_tls_finished_msg_init(&finished);
    if (gquic_tls_cipher_suite_finished_hash(&finished.verify,
                                             cli_state->suite,
                                             &cli_state->conn->out.traffic_sec,
                                             &cli_state->transport) != 0) {
        return -2;
    }
    if (gquic_str_alloc(&buf, gquic_tls_finished_msg_size(&finished)) != 0) {
        ret = -3;
        goto failure;
    }
    if (gquic_tls_finished_msg_serialize(&finished, GQUIC_STR_VAL(&buf), GQUIC_STR_SIZE(&buf)) < 0) {
        ret = -4;
        goto failure;
    }
    if (gquic_tls_mac_md_update(&cli_state->transport, &buf) != 0) {
        ret = -5;
        goto failure;
    }
    if (gquic_tls_conn_write_record(&len, cli_state->conn, GQUIC_TLS_RECORD_TYPE_HANDSHAKE, &buf) != 0) {
        ret = -6;
        goto failure;
    }

    if (gquic_tls_half_conn_set_key(&cli_state->conn->out, GQUIC_ENC_LV_APP, cli_state->suite, &cli_state->traffic_sec) != 0) {
        ret = -7;
        goto failure;
    }
    if (gquic_tls_half_conn_set_traffic_sec(&cli_state->conn->out, cli_state->suite, &cli_state->traffic_sec, 0) != 0) {
        ret = -8;
        goto failure;
    }

    if (!cli_state->conn->cfg->sess_ticket_disabled && cli_state->conn->cfg->cli_sess_cache != NULL) {
        if (gquic_tls_cipher_suite_derive_secret(&cli_state->conn->resumption_sec,
                                                 cli_state->suite,
                                                 &cli_state->transport,
                                                 &cli_state->master_sec,
                                                 &resumption_label) != 0) {
            ret = -9;
            goto failure;
        }
    }

    gquic_str_reset(&buf);
    gquic_tls_finished_msg_reset(&finished);
    return 0;
failure:
    gquic_str_reset(&buf);
    gquic_tls_finished_msg_reset(&finished);
    return ret;
}

static int mutual_protocol(const gquic_str_t *const proto, const gquic_list_t *const perfer_protos) {
    if (proto == NULL || perfer_protos == NULL) {
        return -1;
    }
    gquic_str_t *perfer_proto = NULL;

    GQUIC_LIST_FOREACH(perfer_proto, perfer_protos) {
        if (gquic_str_cmp(proto, perfer_proto) == 0) {
            return 0;
        }
    }

    return -2;
}

static int copy_peer_cert(void *const target, const void *const ref) {
    return gquic_str_copy(target, ref);
}

static int copy_verify(void *const target, const void *const ref) {
    return gquic_str_copy(target, ref);
}


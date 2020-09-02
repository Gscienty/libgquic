/* src/tls/conn.c TLS 连接管理
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "tls/conn.h"
#include "tls/common.h"
#include "tls/alert.h"
#include "tls/hello_req_msg.h"
#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
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
#include "tls/handshake_server.h"
#include "tls/handshake_client.h"
#include "tls/ticket.h"
#include "tls/meta.h"
#include "util/time.h"
#include "util/big_endian.h"
#include "exception.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

static gquic_exception_t gquic_tls_conn_cli_sess_cache_key(gquic_str_t *const, const gquic_net_addr_t *const, const gquic_tls_config_t *const);

static gquic_exception_t gquic_compare_now_asn1_time(const ASN1_TIME *const);
static gquic_exception_t gquic_equal_common_name(const gquic_str_t *const, X509_NAME *const);

static gquic_exception_t gquic_tls_half_conn_inc_seq(gquic_tls_half_conn_t *const);


gquic_exception_t gquic_tls_half_conn_init(gquic_tls_half_conn_t *const half_conn) {
    if (half_conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    half_conn->ver = 0;
    gquic_tls_suite_init(&half_conn->suite);
    gquic_str_init(&half_conn->seq);
    gquic_str_init(&half_conn->addata);
    gquic_tls_suite_init(&half_conn->suite);
    gquic_str_init(&half_conn->traffic_sec);
    half_conn->set_key_self = NULL;
    half_conn->set_key = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_half_conn_encrypt(gquic_str_t *const ret_record,
                                              gquic_tls_half_conn_t *const half_conn,
                                              const gquic_str_t *const record, const gquic_str_t *const payload) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t msg = { 0, NULL };
    gquic_str_t mac = { 0, NULL };
    gquic_str_t sealed = { 0, NULL };
    if (ret_record == NULL || half_conn == NULL || record == NULL || payload == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(ret_record);

    if (half_conn->suite.type == GQUIC_TLS_CIPHER_TYPE_UNKNOW) {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret_record, GQUIC_STR_SIZE(record) + GQUIC_STR_SIZE(payload)));
        memcpy(GQUIC_STR_VAL(ret_record), GQUIC_STR_VAL(record), GQUIC_STR_SIZE(record));
        memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(record), GQUIC_STR_VAL(payload), GQUIC_STR_SIZE(payload));
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    switch (half_conn->suite.type) {
    case GQUIC_TLS_CIPHER_TYPE_STREAM:
        if (half_conn->suite.mac.mac != NULL) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_suite_hmac_hash(&mac, &half_conn->suite, &half_conn->seq, record, payload, NULL))) {
                goto failure;
            }
        }
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_str_alloc(&msg, GQUIC_STR_SIZE(&half_conn->seq) + GQUIC_STR_SIZE(payload) + GQUIC_STR_SIZE(&mac)))) {
            goto failure;
        }
        memcpy(GQUIC_STR_VAL(&msg), GQUIC_STR_VAL(&half_conn->seq), GQUIC_STR_SIZE(&half_conn->seq));
        memcpy(GQUIC_STR_VAL(&msg) + GQUIC_STR_SIZE(&half_conn->seq), GQUIC_STR_VAL(payload), GQUIC_STR_SIZE(payload));
        memcpy(GQUIC_STR_VAL(&msg) + GQUIC_STR_SIZE(&half_conn->seq) + GQUIC_STR_SIZE(payload), GQUIC_STR_VAL(&mac), GQUIC_STR_SIZE(&mac));
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_suite_encrypt(&sealed, &half_conn->suite, &msg))) {
            goto failure;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(ret_record, GQUIC_STR_SIZE(record) + GQUIC_STR_SIZE(&sealed)))) {
            goto failure;
        }
        memcpy(GQUIC_STR_VAL(ret_record), GQUIC_STR_VAL(record), GQUIC_STR_SIZE(record));
        memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(record), GQUIC_STR_VAL(&sealed), GQUIC_STR_SIZE(&sealed));
        break;
    case GQUIC_TLS_CIPHER_TYPE_AEAD:
        if (half_conn->ver == GQUIC_TLS_VERSION_13) {
            u_int8_t tmp_buf[5] = { GQUIC_TLS_RECORD_TYPE_APP_DATA, 0, 0, 0, 0 };
            u_int8_t nonce_payload[8] = { 0 };
            RAND_bytes(nonce_payload, 8);
            // note: aead cipher text struct: | nonce len [1] | nonce[0 XOR 8] | tag[16] | cipher text |
            gquic_str_t nonce = { 8, nonce_payload };
            gquic_str_t tag = { 0, NULL };
            gquic_str_t newly_record = { 5, tmp_buf };
            size_t aead_payload = 1 + 8 + 16 + GQUIC_STR_SIZE(payload);
            memcpy(GQUIC_STR_VAL(&newly_record) + 1, GQUIC_STR_VAL(record) + 1, 2);
            if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(GQUIC_STR_VAL(&newly_record) + 3, &aead_payload, 2))) {
                goto failure;
            }
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_suite_aead_encrypt(&tag, &sealed, &half_conn->suite, &nonce, payload, &newly_record))) {
                goto failure;
            }
            if (GQUIC_ASSERT_CAUSE(exception,
                                   gquic_str_alloc(ret_record,
                                                   GQUIC_STR_SIZE(&newly_record)
                                                   + 1
                                                   + GQUIC_STR_SIZE(&nonce)
                                                   + GQUIC_STR_SIZE(&tag)
                                                   + GQUIC_STR_SIZE(&sealed)))) {
                gquic_str_reset(&tag);
                goto failure;
            }
            memcpy(GQUIC_STR_VAL(ret_record), GQUIC_STR_VAL(&newly_record), GQUIC_STR_SIZE(&newly_record));
            ((u_int8_t *) GQUIC_STR_VAL(ret_record))[GQUIC_STR_SIZE(&newly_record)] = 8;
            memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(&newly_record) + 1, GQUIC_STR_VAL(&nonce), GQUIC_STR_SIZE(&nonce));
            memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(&newly_record) + 1 + GQUIC_STR_SIZE(&nonce), GQUIC_STR_VAL(&tag), GQUIC_STR_SIZE(&tag));
            memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(&newly_record) + 1 + GQUIC_STR_SIZE(&nonce) + GQUIC_STR_SIZE(&tag), GQUIC_STR_VAL(&sealed), GQUIC_STR_SIZE(&sealed));
            gquic_str_reset(&tag);
        }
        else {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
            goto failure;
        }
        break;
    default:
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_TLS_CIPHER_TYPE_UNKNOW);
        goto failure;
    }

    size_t truly_payload_len = GQUIC_STR_SIZE(ret_record) - 5;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(GQUIC_STR_VAL(ret_record) + 3, &truly_payload_len, 2))) {
        goto failure;
    }

    gquic_tls_half_conn_inc_seq(half_conn);

    gquic_str_reset(&msg);
    gquic_str_reset(&mac);
    gquic_str_reset(&sealed);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&msg);
    gquic_str_reset(&mac);
    gquic_str_reset(&sealed);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_half_conn_set_key(gquic_tls_half_conn_t *const half_conn, const u_int8_t enc_lv,
                                              const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const secret) {
    if (half_conn == NULL || cipher_suite == NULL || secret == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (half_conn->set_key == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(half_conn->set_key(half_conn->set_key_self, enc_lv, cipher_suite, secret));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_half_conn_set_traffic_sec(gquic_tls_half_conn_t *const half_conn,
                                                      const gquic_tls_cipher_suite_t *const cipher_suite, const gquic_str_t *const secret, bool is_read) {
    size_t i;
    gquic_str_t key = { 0, NULL };
    gquic_str_t iv = { 0, NULL };
    if (half_conn == NULL || cipher_suite == NULL || secret == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&half_conn->traffic_sec);
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&half_conn->traffic_sec, secret));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cipher_suite_traffic_key(&key, &iv, cipher_suite, secret));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_suite_ctor(&half_conn->suite, cipher_suite, &iv, &key, NULL, is_read));
    gquic_str_reset(&half_conn->seq);
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&half_conn->seq, 8));
    for (i = 0; i < GQUIC_STR_SIZE(&half_conn->seq); i++) {
        ((u_int8_t *) GQUIC_STR_VAL(&half_conn->seq))[i] = 0;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_init(gquic_tls_conn_t *const conn) {
    if (conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    conn->addr = NULL;
    conn->cfg = NULL;
    conn->is_client = false;
    conn->handshake_status = 0;
    conn->ver = 0;
    conn->have_vers = 0;
    conn->handshakes = 0;
    conn->did_resume = false;
    conn->cipher_suite = 0;
    gquic_str_init(&conn->ocsp_resp);
    gquic_list_head_init(&conn->scts);
    gquic_list_head_init(&conn->peer_certs);
    gquic_list_head_init(&conn->verified_chains);
    gquic_str_init(&conn->ser_name);
    conn->sec_renegortiation = 0;
    gquic_tls_ekm_init(&conn->ekm);
    gquic_str_init(&conn->resumption_sec);
    conn->cli_finished_is_first = 0;
    gquic_tls_half_conn_init(&conn->in);
    gquic_tls_half_conn_init(&conn->out);
    conn->sent_size = 0;
    conn->sent_pkg_count = 0;
    conn->buffering = 0;
    gquic_str_init(&conn->cli_proto);
    conn->cli_proto_fallback = 0;
    pthread_mutex_init(&conn->mtx, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);

}

gquic_exception_t gquic_tls_half_conn_decrypt(gquic_str_t *const ret, u_int8_t *const record_type,
                                              gquic_tls_half_conn_t *const half_conn, const gquic_str_t *const record) {
    gquic_str_t payload = { GQUIC_STR_SIZE(record) - 5, GQUIC_STR_VAL(record) + 5 };
    if (ret == NULL || record_type == NULL || half_conn == NULL || record == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *record_type = GQUIC_STR_FIRST_BYTE(record);

    if (half_conn->suite.type != GQUIC_TLS_CIPHER_TYPE_UNKNOW) {
        switch (half_conn->suite.type) {
        case GQUIC_TLS_CIPHER_TYPE_STREAM:
            {
                gquic_str_t plain_text = { 0, NULL };
                GQUIC_ASSERT_FAST_RETURN(gquic_tls_suite_decrypt(&plain_text, &half_conn->suite, &payload));
                if (half_conn->suite.mac.mac != NULL) {
                    size_t mac_size = HMAC_size(half_conn->suite.mac.mac);
                    if (GQUIC_STR_SIZE(&payload) < mac_size) {
                        gquic_str_reset(&plain_text);
                        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_MAC_LENGTH_UNEXCEPTED);
                    }
                    gquic_str_t remote_mac = { mac_size, GQUIC_STR_VAL(&plain_text) + GQUIC_STR_SIZE(&plain_text) - mac_size };
                    gquic_str_t record_header = { 5, GQUIC_STR_VAL(record) };
                    gquic_str_t local_mac = { 0, NULL };
                    plain_text.size -= mac_size;
                    GQUIC_ASSERT_FAST_RETURN(gquic_tls_suite_hmac_hash(&local_mac, &half_conn->suite, &half_conn->seq, &record_header, &payload, NULL));
                    if (gquic_str_cmp(&local_mac, &remote_mac) != 0) {
                        gquic_str_reset(&local_mac);
                        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_MAC_NOT_EQUAL);
                    }
                    gquic_str_reset(&local_mac);
                }
            }
            break;
        case GQUIC_TLS_CIPHER_TYPE_AEAD:
            {
                gquic_str_t nonce = { 0, NULL };
                gquic_str_t addata = { 0, NULL };
                gquic_str_t tag = { 0, NULL };
                addata.size = 5;
                addata.val = GQUIC_STR_VAL(record);
                nonce.size = GQUIC_STR_FIRST_BYTE(&payload);
                nonce.val = GQUIC_STR_VAL(&payload) + 1;
                payload.size -= GQUIC_STR_SIZE(&nonce) + 1;
                payload.val += GQUIC_STR_SIZE(&nonce) + 1;
                tag.size = 16;
                tag.val = GQUIC_STR_VAL(&payload);
                payload.size -= 16;
                payload.val += 16;
                GQUIC_ASSERT_FAST_RETURN(gquic_tls_suite_aead_decrypt(ret, &half_conn->suite, &nonce, &tag, &payload, &addata));
            }
            break;
        default:
            GQUIC_PROCESS_DONE(GQUIC_TLS_CIPHER_TYPE_UNKNOW);
        }
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(ret, GQUIC_STR_SIZE(&payload)));
        memcpy(GQUIC_STR_VAL(ret), GQUIC_STR_VAL(&payload), GQUIC_STR_SIZE(&payload));
    }
    gquic_tls_half_conn_inc_seq(half_conn);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_load_session(gquic_str_t *const cache_key, gquic_tls_client_sess_state_t **const sess,
                                              gquic_str_t *const early_sec, gquic_str_t *const binder_key,
                                              const gquic_tls_conn_t *const conn, gquic_tls_client_hello_msg_t *const hello) {
    if (conn == NULL || cache_key == NULL || sess == NULL || early_sec == NULL || binder_key == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *sess = NULL;
    gquic_str_init(cache_key);
    gquic_str_init(early_sec);
    gquic_str_init(binder_key);
    if (conn->cfg->sess_ticket_disabled || conn->cfg->cli_sess_cache == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    hello->ticket_supported = true;
    if ((*(u_int16_t *) GQUIC_LIST_FIRST(&hello->supported_versions)) == GQUIC_TLS_VERSION_13) {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&hello->psk_modes, 1));
        *(u_int8_t *) GQUIC_STR_VAL(&hello->psk_modes) = 1;
    }
    if (conn->handshakes != 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_cli_sess_cache_key(cache_key, conn->addr, conn->cfg));
    if (conn->cfg->cli_sess_cache->get(sess, conn->cfg->cli_sess_cache->self, cache_key) != 0 && *sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    bool ver_avail = false;
    u_int16_t *supported_ver;
    GQUIC_LIST_FOREACH(supported_ver, &hello->supported_versions) {
        if (*supported_ver == (*sess)->ver) {
            ver_avail = true;
            break;
        }
    }
    if (!ver_avail) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    if (conn->cfg->insecure_skiy_verify == 0) {
        if (gquic_list_head_empty(&(*sess)->verified_chains)) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        if (gquic_list_head_empty(&(*sess)->ser_certs)) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SERVER_CERTS_EMPTY);
        }
        X509 *ser_cert = *(X509 **) GQUIC_LIST_FIRST(&(*sess)->ser_certs);
        int cmp = gquic_compare_now_asn1_time(X509_get_notAfter(ser_cert));
        if (cmp == 1) {
            conn->cfg->cli_sess_cache->put(conn->cfg->cli_sess_cache->self, cache_key, NULL);
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        else if (cmp == -2) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_SERVER_CERTS_EXPIRED);
        }

        if (!gquic_equal_common_name(&conn->cfg->ser_name, X509_get_subject_name(ser_cert))) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    if ((*sess)->ver != GQUIC_TLS_VERSION_13) {
        u_int16_t *hello_cipher_suite;
        int finded_cipher_suite = 0;
        GQUIC_LIST_FOREACH(hello_cipher_suite, &hello->cipher_suites) {
            if (*hello_cipher_suite == (*sess)->cipher_suite) {
                finded_cipher_suite = 1;
                break;
            }
        }
        if (finded_cipher_suite == 0) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }

        gquic_str_copy(&hello->sess_ticket, &(*sess)->sess_ticket);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    if (time(NULL) > (*sess)->use_by) {
        conn->cfg->cli_sess_cache->put(conn->cfg->cli_sess_cache->self, cache_key, NULL);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    int64_t ticket_age;
    gquic_time_since_milli(&ticket_age, &(*sess)->received_at);
    gquic_tls_psk_identity_t *identity = NULL;
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &identity, sizeof(gquic_tls_psk_identity_t)));
    gquic_str_init(&identity->label);
    gquic_str_copy(&identity->label, &(*sess)->sess_ticket);
    identity->obfuscated_ticket_age = ticket_age + (*sess)->age_add;
    gquic_list_insert_before(&hello->psk_identities, identity);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_set_alt_record(gquic_tls_conn_t *const conn) {
    if (conn == NULL || conn->cfg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    conn->in.set_key_self = conn->cfg->alt_record.self;
    conn->in.set_key = conn->cfg->alt_record.set_rkey;
    conn->out.set_key_self = conn->cfg->alt_record.self;
    conn->out.set_key = conn->cfg->alt_record.set_wkey;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_read_handshake(void **const msg, gquic_tls_conn_t *const conn) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t data = { 0, NULL };
    if (msg == NULL || conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->cfg->alt_record.read_handshake_msg != NULL
        && GQUIC_ASSERT_CAUSE(exception, conn->cfg->alt_record.read_handshake_msg(&data, conn->cfg->alt_record.self))) {
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_STR_SIZE(&data) == 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HANDSHAKE_MESSAGE_EMPTY);
    }
    
    switch (GQUIC_STR_FIRST_BYTE(&data)) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_hello_req_msg_alloc((gquic_tls_hello_req_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_hello_msg_alloc((gquic_tls_client_hello_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_server_hello_msg_alloc((gquic_tls_server_hello_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_new_sess_ticket_msg_alloc((gquic_tls_new_sess_ticket_msg_t **) msg))) {
                goto failure;
            }
        }
        else {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cert_msg_alloc((gquic_tls_cert_msg_t **) msg))) {
                goto failure;
            }
        }
        else {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cert_req_msg_alloc((gquic_tls_cert_req_msg_t **) msg))) {
                goto failure;
            }
        }
        else {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_VERSION_TOO_OLD);
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cert_status_msg_alloc((gquic_tls_cert_status_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_server_key_exchange_msg_alloc((gquic_tls_server_key_exchange_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_server_hello_done_msg_alloc((gquic_tls_server_hello_done_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_client_key_exchange_msg_alloc((gquic_tls_client_key_exchange_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_cert_verify_msg_alloc((gquic_tls_cert_verify_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_next_proto_msg_alloc((gquic_tls_next_proto_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_finished_msg_alloc((gquic_tls_finished_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_encrypt_ext_msg_alloc((gquic_tls_encrypt_ext_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_end_of_early_data_msg_alloc((gquic_tls_end_of_early_data_msg_t **) msg))) {
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE:
        if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_key_update_msg_alloc((gquic_tls_key_update_msg_t **) msg))) {
            goto failure;
        }
        break;
    default:
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
        goto failure;
    }
    GQUIC_TLS_MSG_INIT(*msg);
    gquic_reader_str_t reader = data;
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_MSG_DESERIALIZE(*msg, &reader))) {
        GQUIC_PROCESS_DONE(exception);
    }

    gquic_str_reset(&data);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&data);
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_tls_conn_cli_sess_cache_key(gquic_str_t *const ret, const gquic_net_addr_t *const addr, const gquic_tls_config_t *const cfg) {
    if (ret == NULL || addr == NULL || cfg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&cfg->ser_name) > 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(ret, &cfg->ser_name));
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_net_addr_to_str(addr, ret));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_compare_now_asn1_time(const ASN1_TIME *const ref_time) {
    gquic_exception_t cmp;
    ASN1_TIME *cur = ASN1_TIME_new();
    ASN1_TIME_set(cur, time(NULL));
    cmp = ASN1_TIME_compare(cur, ref_time);
    ASN1_TIME_free(cur);
    return cmp;
}

static gquic_exception_t gquic_equal_common_name(const gquic_str_t *const n1, X509_NAME *const n2) {
    gquic_str_t n2_str;
    int ret = X509_NAME_get_text_by_NID(n2, NID_commonName, NULL, 0);
    if ((size_t) ret != GQUIC_STR_SIZE(n1)) {
        return 0;
    }
    if (gquic_str_alloc(&n2_str, ret) != 0) {
        return 0;
    }
    X509_NAME_get_text_by_NID(n2, NID_commonName, GQUIC_STR_VAL(&n2_str), GQUIC_STR_SIZE(&n2_str));
    ret = memcmp(GQUIC_STR_VAL(&n2_str), GQUIC_STR_VAL(n1), GQUIC_STR_SIZE(n1));
    gquic_str_reset(&n2_str);
    return ret == 0;
}

gquic_exception_t gquic_tls_conn_write_record(size_t *writed_size, gquic_tls_conn_t *const conn, u_int8_t record_type, const gquic_str_t *const data) {
    if (conn == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *writed_size = 0;
    if (conn->cfg->alt_record.write_record != NULL) {
        if (record_type == GQUIC_TLS_RECORD_TYPE_CHANGE_CIPHER_SEPC) {
            *writed_size = GQUIC_STR_SIZE(data);
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
        GQUIC_ASSERT_FAST_RETURN(conn->cfg->alt_record.write_record(writed_size, conn->cfg->alt_record.self, data));
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
}

gquic_exception_t gquic_tls_conn_write_max_write_size(size_t *const ret, const gquic_tls_conn_t *const conn, const u_int8_t record_type) {
    if (ret == NULL || conn == NULL || conn->cfg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *ret = 0;
    if (conn->cfg->dynamic_record_sizing_disabled || record_type != GQUIC_TLS_RECORD_TYPE_APP_DATA) {
        *ret = GQUIC_MAX_PLAINTEXT;
    }
    if (conn->sent_size >= GQUIC_RECORD_SIZE_BOOST_THRESHOLD) {
        *ret = GQUIC_MAX_PLAINTEXT;
    }
    size_t payload_size = GQUIC_MSS_EST - 5 - gquic_tls_suite_nonce_size(&conn->out.suite);
    switch (conn->out.suite.type) {
    case GQUIC_TLS_CIPHER_TYPE_STREAM:
        payload_size -= gquic_tls_suite_mac_size(&conn->out.suite);
        break;
    case GQUIC_TLS_CIPHER_TYPE_AEAD:
        payload_size -= 16; // AEAD tag size
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_TLS_RECORD_TYPE_INVALID_UNEXCEPTED);
    }
    if (conn->sent_pkg_count >= 1000) {
        *ret = GQUIC_MAX_PLAINTEXT;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    *ret = payload_size * (conn->sent_pkg_count + 1);
    if (*ret > GQUIC_MAX_PLAINTEXT) {
        *ret = GQUIC_MAX_PLAINTEXT;
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_send_alert(gquic_tls_conn_t *const conn, u_int8_t alert) {
    if (conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->cfg->alt_record.send_alert == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_ASSERT_FAST_RETURN(conn->cfg->alt_record.send_alert(conn->cfg->alt_record.self, alert));
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_tls_half_conn_inc_seq(gquic_tls_half_conn_t *const half_conn) {
    if (half_conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    size_t i;
    for (i = 7; i > 0; i--) {
        if (++((unsigned char *) GQUIC_STR_VAL(&half_conn->seq))[i] != 0) {
            GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
}

gquic_exception_t gquic_tls_conn_verify_ser_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    X509 **cert_storage = NULL;
    bool first = true;
    if (conn == NULL || certs == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&conn->peer_certs);

    GQUIC_LIST_FOREACH(cert_storage, certs) {
        X509 *x509 = *cert_storage;
        if (first) {
            int pubkey_id = EVP_PKEY_id(X509_get_pubkey(x509));
            if (pubkey_id != EVP_PKEY_RSA
                && pubkey_id != EVP_PKEY_EC
                && pubkey_id != EVP_PKEY_ED25519) {
                gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_BAD_X509);
            }
            first = false;
        }
        X509 **peer_cert = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &peer_cert, sizeof(X509 *)))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            GQUIC_PROCESS_DONE(exception);
        }
        *peer_cert = X509_dup(*cert_storage);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&conn->peer_certs, peer_cert))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            GQUIC_PROCESS_DONE(exception);
        }
    }
    if (conn->cfg->verify_peer_certs != NULL) {
        if (GQUIC_ASSERT_CAUSE(exception, conn->cfg->verify_peer_certs(&conn->peer_certs, &conn->verified_chains))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
            GQUIC_PROCESS_DONE(exception);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_process_cli_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    X509 **cert_storage = NULL;
    if (conn == NULL || certs == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&conn->peer_certs);

    if (gquic_list_head_empty(certs) && gquic_tls_requires_cli_cert(conn->cfg->cli_auth)) {
        gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CLIENT_CERTS_EMPTY);
    }

    GQUIC_LIST_FOREACH(cert_storage, certs) {
        X509 **peer_cert = NULL;
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &peer_cert, sizeof(X509 *)))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            GQUIC_PROCESS_DONE(exception);
        }
        *peer_cert = X509_dup(*cert_storage);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_insert_before(&conn->peer_certs, peer_cert))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            GQUIC_PROCESS_DONE(exception);
        }
    }

    if (conn->cfg->verify_peer_certs != NULL) {
        if (GQUIC_ASSERT_CAUSE(exception, conn->cfg->verify_peer_certs(&conn->peer_certs, &conn->verified_chains))) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
            GQUIC_PROCESS_DONE(exception);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_handshake(gquic_tls_conn_t *const conn) {
    if (conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&conn->mtx);
    if (conn->is_client) {
        GQUIC_ASSERT_FAST_RETURN(gquic_tls_client_handshake(conn));
    }
    else {
        GQUIC_ASSERT_FAST_RETURN(gquic_tls_server_handshake(conn));
    }
    conn->handshakes++;
    pthread_mutex_unlock(&conn->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_tls_conn_get_sess_ticket(gquic_str_t *const msg, gquic_tls_conn_t *const conn) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_tls_sess_state_t state;
    X509 **peer_cert = NULL;
    X509 **cert = NULL;
    gquic_tls_new_sess_ticket_msg_t *ticket = NULL;
    if (msg == NULL || conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->is_client || conn->handshake_status != 1 || conn->cfg->alt_record.self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (conn->cfg->sess_ticket_disabled) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_new_sess_ticket_msg_alloc(&ticket));
    GQUIC_TLS_MSG_INIT(ticket);
    gquic_tls_sess_state_init(&state);
    GQUIC_LIST_FOREACH(peer_cert, &conn->peer_certs) {
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &cert, sizeof(X509 *)));
        *cert = *(X509 **) peer_cert;
        GQUIC_ASSERT_FAST_RETURN(gquic_list_insert_before(&state.cert.certs, cert));
    }
    // TODO copy ocsp and scts
    state.cipher_suite = conn->cipher_suite;
    GQUIC_ASSERT_FAST_RETURN(gquic_str_copy(&state.resumption_sec, &conn->resumption_sec));
    state.create_at = time(NULL);

    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&ticket->label, gquic_tls_sess_state_size(&state)))) {
        goto failure;
    }
    gquic_writer_str_t writer = ticket->label;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_sess_state_serialize(&state, &writer))) {
        goto failure;
    }
    ticket->lifetime = 7 * 24 * 60;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_msg_combine_serialize(msg, ticket))) {
        goto failure;
    }

    gquic_tls_msg_release(ticket);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_tls_msg_release(ticket);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_conn_encrypt_ticket(gquic_str_t *const encrypted, gquic_tls_conn_t *const conn, const gquic_str_t *const state) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX *hmac = NULL;
    int size = 0;
    gquic_tls_ticket_key_t *key = NULL;
    if (encrypted == NULL || conn == NULL || state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if (EVP_CIPHER_CTX_init(ctx) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if ((hmac = HMAC_CTX_new()) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(encrypted, 16 + 16 + GQUIC_STR_SIZE(state) + 32))) {
        goto failure;
    }
    if (RAND_bytes(GQUIC_STR_VAL(encrypted) + 16, 16) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RANDOM_FAILED);
        goto failure;
    }
    key = GQUIC_LIST_FIRST(&conn->cfg->sess_ticket_keys);
    memcpy(GQUIC_STR_VAL(encrypted), key->name, 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->aes_key, GQUIC_STR_VAL(encrypted) + 16) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_EncryptUpdate(ctx, GQUIC_STR_VAL(encrypted) + 16 + 16, &size, GQUIC_STR_VAL(state), GQUIC_STR_SIZE(state)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_EncryptFinal_ex(ctx, GQUIC_STR_VAL(encrypted) + 16 + 16 + size, &size) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (HMAC_Init_ex(hmac, key->hmac_key, 16, EVP_sha256(), NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }
    if (HMAC_Update(hmac, GQUIC_STR_VAL(encrypted), GQUIC_STR_SIZE(encrypted) - 32) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }
    if (HMAC_Final(hmac, GQUIC_STR_VAL(encrypted) + GQUIC_STR_SIZE(encrypted) - 32, (u_int32_t *) &size) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_conn_decrypt_ticket(gquic_str_t *const plain, bool *const is_oldkey, gquic_tls_conn_t *const conn, const gquic_str_t *const encrypted) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    const gquic_str_t key_name = { 16, GQUIC_STR_VAL(encrypted) };
    const gquic_str_t iv = { 16, GQUIC_STR_VAL(encrypted) + 16 };
    const gquic_str_t mac = { 32, GQUIC_STR_VAL(encrypted) + GQUIC_STR_SIZE(encrypted) - 32 };
    const gquic_str_t cipher_text = { GQUIC_STR_SIZE(encrypted) - 16 - 16 - 32, GQUIC_STR_VAL(encrypted) + 16 + 16 };
    const gquic_list_t *keys = NULL;
    const gquic_tls_ticket_key_t *key = NULL;
    gquic_tls_ticket_key_t *key_itr = NULL;
    u_int32_t size = 0;
    u_int8_t mac_cnt[32] = { 0 };
    const gquic_str_t mac_expect = { 32, mac_cnt };
    HMAC_CTX *hmac = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    if (plain == NULL || is_oldkey == NULL || conn == NULL || encrypted == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(encrypted) < 16 + 16 + 32) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if ((hmac = HMAC_CTX_new()) == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    keys = &conn->cfg->sess_ticket_keys;
    GQUIC_LIST_FOREACH(key_itr, keys) {
        const gquic_str_t name = { 16, key_itr->name };
        if (gquic_str_cmp(&key_name, &name) == 0) {
            key = key_itr;
            break;
        }
    }
    if (key == NULL) {
        *is_oldkey = false;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (HMAC_Init_ex(hmac, key->hmac_key, 16, EVP_sha256(), NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }
    if (HMAC_Update(hmac, GQUIC_STR_VAL(encrypted), GQUIC_STR_SIZE(encrypted) - 32) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }
    if (HMAC_Final(hmac, mac_cnt, &size) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_HMAC_FAILED);
        goto failure;
    }
    if (gquic_str_cmp(&mac_expect, &mac) != 0) {
        *is_oldkey = false;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->aes_key, GQUIC_STR_VAL(&iv)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(plain, GQUIC_STR_SIZE(&cipher_text)))) {
        goto failure;
    }
    if (EVP_DecryptUpdate(ctx, GQUIC_STR_VAL(plain), (int *) &size, GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (EVP_DecryptFinal_ex(ctx, GQUIC_STR_VAL(plain) + size, (int *) &size) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    *is_oldkey = true;

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    *is_oldkey = false;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_tls_conn_handle_post_handshake_msg(gquic_tls_conn_t *const conn) {
    void *msg = NULL;
    if (conn == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_tls_conn_read_handshake(&msg, conn));

    switch (GQUIC_TLS_MSG_META(msg).type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        // TODO
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE:
        // TODO
    default:
        gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
    }

    gquic_tls_msg_release(msg);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

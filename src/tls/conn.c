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
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

static int gquic_tls_conn_cli_sess_cache_key(gquic_str_t *const, const gquic_net_addr_t *const, const gquic_tls_config_t *const);

static int gquic_compare_now_asn1_time(const ASN1_TIME *const);
static int gquic_equal_common_name(const gquic_str_t *const, X509_NAME *const);

static int gquic_tls_half_conn_inc_seq(gquic_tls_half_conn_t *const);


int gquic_tls_half_conn_init(gquic_tls_half_conn_t *const half_conn) {
    if (half_conn == NULL) {
        return -1;
    }
    half_conn->ver = 0;
    gquic_tls_suite_init(&half_conn->suite);
    gquic_str_init(&half_conn->seq);
    gquic_str_init(&half_conn->addata);
    gquic_tls_suite_init(&half_conn->suite);
    gquic_str_init(&half_conn->traffic_sec);
    half_conn->set_key_self = NULL;
    half_conn->set_key = NULL;
    return 0;
}

int gquic_tls_half_conn_encrypt(gquic_str_t *const ret_record,
                                gquic_tls_half_conn_t *const half_conn,
                                const gquic_str_t *const record,
                                const gquic_str_t *const payload) {
    int ret = 0;
    gquic_str_t msg = { 0, NULL };
    gquic_str_t mac = { 0, NULL };
    gquic_str_t sealed = { 0, NULL };
    if (ret_record == NULL || half_conn == NULL || record == NULL || payload == NULL) {
        return -1;
    }
    if (gquic_str_init(ret_record) != 0) {
        return -2;
    }
    if (half_conn->suite.type == GQUIC_TLS_CIPHER_TYPE_UNKNOW) {
        if (gquic_str_alloc(ret_record, GQUIC_STR_SIZE(record) + GQUIC_STR_SIZE(payload)) != 0) {
            return -3;
        }
        memcpy(GQUIC_STR_VAL(ret_record), GQUIC_STR_VAL(record), GQUIC_STR_SIZE(record));
        memcpy(GQUIC_STR_VAL(ret_record) + GQUIC_STR_SIZE(record), GQUIC_STR_VAL(payload), GQUIC_STR_SIZE(payload));
        return 0;
    }
    switch (half_conn->suite.type) {
    case GQUIC_TLS_CIPHER_TYPE_STREAM:
        if (half_conn->suite.mac.mac != NULL) {
            if (gquic_tls_suite_hmac_hash(&mac, &half_conn->suite, &half_conn->seq, record, payload, NULL) != 0) {
                ret = -4;
                goto failure;
            }
        }
        if (gquic_str_alloc(&msg, GQUIC_STR_SIZE(&half_conn->seq) + GQUIC_STR_SIZE(payload) + GQUIC_STR_SIZE(&mac)) != 0) {
            ret = -5;
            goto failure;
        }
        memcpy(GQUIC_STR_VAL(&msg), GQUIC_STR_VAL(&half_conn->seq), GQUIC_STR_SIZE(&half_conn->seq));
        memcpy(GQUIC_STR_VAL(&msg) + GQUIC_STR_SIZE(&half_conn->seq), GQUIC_STR_VAL(payload), GQUIC_STR_SIZE(payload));
        memcpy(GQUIC_STR_VAL(&msg) + GQUIC_STR_SIZE(&half_conn->seq) + GQUIC_STR_SIZE(payload), GQUIC_STR_VAL(&mac), GQUIC_STR_SIZE(&mac));
        if (gquic_tls_suite_encrypt(&sealed, &half_conn->suite, &msg) != 0) {
            ret = -6;
            goto failure;
        }
        if (gquic_str_alloc(ret_record, GQUIC_STR_SIZE(record) + GQUIC_STR_SIZE(&sealed)) != 0) {
            ret = -7;
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
            if (gquic_big_endian_transfer(GQUIC_STR_VAL(&newly_record) + 3, &aead_payload, 2) != 0) {
                ret = -8;
                goto failure;
            }
            if ((ret = gquic_tls_suite_aead_encrypt(&tag, &sealed, &half_conn->suite, &nonce, payload, &newly_record)) != 0) {
                ret += -9 * 100;
                goto failure;
            }
            if (gquic_str_alloc(ret_record, GQUIC_STR_SIZE(&newly_record) + 1 + GQUIC_STR_SIZE(&nonce) + GQUIC_STR_SIZE(&tag) + GQUIC_STR_SIZE(&sealed)) != 0) {
                gquic_str_reset(&tag);
                ret = -10;
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
            ret = -11;
            goto failure;
        }
        break;
    default:
        ret = -12;
        goto failure;
    }

    size_t truly_payload_len = GQUIC_STR_SIZE(ret_record) - 5;
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(ret_record) + 3, &truly_payload_len, 2) != 0) {
        ret = -13;
        goto failure;
    }

    gquic_tls_half_conn_inc_seq(half_conn);

    gquic_str_reset(&msg);
    gquic_str_reset(&mac);
    gquic_str_reset(&sealed);
    return 0;
failure:
    gquic_str_reset(&msg);
    gquic_str_reset(&mac);
    gquic_str_reset(&sealed);
    return ret;
}

int gquic_tls_half_conn_set_key(gquic_tls_half_conn_t *const half_conn,
                                const u_int8_t enc_lv,
                                const gquic_tls_cipher_suite_t *const cipher_suite,
                                const gquic_str_t *const secret) {
    if (half_conn == NULL || cipher_suite == NULL || secret == NULL) {
        return -1;
    }
    if (half_conn->set_key == NULL) {
        return 0;
    }

    return half_conn->set_key(half_conn->set_key_self, enc_lv, cipher_suite, secret);
}

int gquic_tls_half_conn_set_traffic_sec(gquic_tls_half_conn_t *const half_conn,
                                        const gquic_tls_cipher_suite_t *const cipher_suite,
                                        const gquic_str_t *const secret,
                                        int is_read) {
    gquic_str_t key = { 0, NULL };
    gquic_str_t iv = { 0, NULL };
    if (half_conn == NULL || cipher_suite == NULL || secret == NULL) {
        return -1;
    }
    gquic_str_reset(&half_conn->traffic_sec);
    if (gquic_str_copy(&half_conn->traffic_sec, secret) != 0) {
        return -2;
    }
    if (gquic_tls_cipher_suite_traffic_key(&key, &iv, cipher_suite, secret) != 0) {
        return -3;
    }
    if (gquic_tls_suite_assign(&half_conn->suite, cipher_suite, &iv, &key, NULL, is_read) != 0) {
        return -4;
    }
    gquic_str_reset(&half_conn->seq);
    if (gquic_str_alloc(&half_conn->seq, 8) != 0) {
        return -5;
    }
    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(&half_conn->seq); i++) {
        ((u_int8_t *) GQUIC_STR_VAL(&half_conn->seq))[i] = 0;
    }
    return 0;
}

int gquic_tls_conn_init(gquic_tls_conn_t *const conn) {
    if (conn == NULL) {
        return -1;
    }
    conn->addr = NULL;
    conn->cfg = NULL;
    conn->is_client = 0;
    conn->handshake_status = 0;
    conn->ver = 0;
    conn->have_vers = 0;
    conn->handshakes = 0;
    conn->did_resume = 0;
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
    sem_init(&conn->handshake_mtx, 0, 1);
    return 0;

}

int gquic_tls_half_conn_decrypt(gquic_str_t *const ret,
                                u_int8_t *const record_type,
                                gquic_tls_half_conn_t *const half_conn,
                                const gquic_str_t *const record) {
    gquic_str_t payload = { GQUIC_STR_SIZE(record) - 5, GQUIC_STR_VAL(record) + 5 };
    if (ret == NULL || record_type == NULL || half_conn == NULL || record == NULL) {
        return -1;
    }
    *record_type = GQUIC_STR_FIRST_BYTE(record);

    if (half_conn->suite.type != GQUIC_TLS_CIPHER_TYPE_UNKNOW) {
        switch (half_conn->suite.type) {
        case GQUIC_TLS_CIPHER_TYPE_STREAM:
            {
                gquic_str_t plain_text = { 0, NULL };
                if (gquic_tls_suite_decrypt(&plain_text, &half_conn->suite, &payload) != 0) {
                    return -2;
                }
                if (half_conn->suite.mac.mac != NULL) {
                    size_t mac_size = HMAC_size(half_conn->suite.mac.mac);
                    if (GQUIC_STR_SIZE(&payload) < mac_size) {
                        gquic_str_reset(&plain_text);
                        return -3;
                    }
                    gquic_str_t remote_mac = { mac_size, GQUIC_STR_VAL(&plain_text) + GQUIC_STR_SIZE(&plain_text) - mac_size };
                    gquic_str_t record_header = { 5, GQUIC_STR_VAL(record) };
                    gquic_str_t local_mac = { 0, NULL };
                    plain_text.size -= mac_size;
                    if (gquic_tls_suite_hmac_hash(&local_mac, &half_conn->suite, &half_conn->seq, &record_header, &payload, NULL) != 0) {
                        return -4;
                    }
                    if (gquic_str_cmp(&local_mac, &remote_mac) != 0) {
                        gquic_str_reset(&local_mac);
                        return -5;
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
                if (gquic_tls_suite_aead_decrypt(ret, &half_conn->suite, &nonce, &tag, &payload, &addata) != 0) {
                    return -6;
                }
            }
            break;
        default:
            return -7;
        }
    }
    else {
        if (gquic_str_alloc(ret, GQUIC_STR_SIZE(&payload)) != 0) {
            return -8;
        }
        memcpy(GQUIC_STR_VAL(ret), GQUIC_STR_VAL(&payload), GQUIC_STR_SIZE(&payload));
    }
    gquic_tls_half_conn_inc_seq(half_conn);

    return 0;
}

int gquic_tls_conn_load_session(gquic_str_t *const cache_key,
                                gquic_tls_client_sess_state_t **const sess,
                                gquic_str_t *const early_sec,
                                gquic_str_t *const binder_key,
                                const gquic_tls_conn_t *const conn,
                                gquic_tls_client_hello_msg_t *const hello) {
    if (conn == NULL || cache_key == NULL || sess == NULL || early_sec == NULL || binder_key == NULL) {
        return -1;
    }
    *sess = NULL;
    gquic_str_init(cache_key);
    gquic_str_init(early_sec);
    gquic_str_init(binder_key);
    if (conn->cfg->sess_ticket_disabled || conn->cfg->cli_sess_cache == NULL) {
        return 0;
    }
    hello->ticket_supported = 1;
    if ((*(u_int16_t *) GQUIC_LIST_FIRST(&hello->supported_versions)) == GQUIC_TLS_VERSION_13) {
        if (gquic_str_alloc(&hello->psk_modes, 1) != 0) {
            return -2;
        }
        *(u_int8_t *) GQUIC_STR_VAL(&hello->psk_modes) = 1;
    }
    if (conn->handshakes != 0) {
        return 0;
    }
    if (gquic_tls_conn_cli_sess_cache_key(cache_key, conn->addr, conn->cfg) != 0) {
        return -3;
    }
    if (conn->cfg->cli_sess_cache->get(sess, conn->cfg->cli_sess_cache->self, cache_key) != 0 && *sess == NULL) {
        return 0;
    }
    int ver_avail = 0;
    u_int16_t *supported_ver;
    GQUIC_LIST_FOREACH(supported_ver, &hello->supported_versions) {
        if (*supported_ver == (*sess)->ver) {
            ver_avail = 1;
            break;
        }
    }
    if (ver_avail == 0) {
        return 0;
    }

    if (conn->cfg->insecure_skiy_verify == 0) {
        if (gquic_list_head_empty(&(*sess)->verified_chains)) {
            return 0;
        }
        if (gquic_list_head_empty(&(*sess)->ser_certs)) {
            return -4;
        }
        gquic_str_t *ser_cert = GQUIC_LIST_FIRST(&(*sess)->ser_certs);
        X509 *x509_ser_cert = d2i_X509(NULL, (unsigned char const **) &ser_cert->val, GQUIC_STR_SIZE(ser_cert));
        int cmp = gquic_compare_now_asn1_time(X509_get_notAfter(x509_ser_cert));
        if (cmp == 1) {
            X509_free(x509_ser_cert);
            conn->cfg->cli_sess_cache->put(conn->cfg->cli_sess_cache->self, cache_key, NULL);
            return 0;
        }
        else if (cmp == -2) {
            X509_free(x509_ser_cert);
            return -5;
        }

        if (!gquic_equal_common_name(&conn->cfg->ser_name,
                                X509_get_subject_name(x509_ser_cert))) {
            return 0;
        }
        X509_free(x509_ser_cert);
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
            return 0;
        }

        gquic_str_copy(&hello->sess_ticket, &(*sess)->sess_ticket);
        return 0;
    }

    if (time(NULL) > (*sess)->use_by) {
        conn->cfg->cli_sess_cache->put(conn->cfg->cli_sess_cache->self, cache_key, NULL);
        return 0;
    }
    int64_t ticket_age;
    gquic_time_since_milli(&ticket_age, &(*sess)->received_at);
    gquic_tls_psk_identity_t *identity = gquic_list_alloc(sizeof(gquic_tls_psk_identity_t));
    if (identity == NULL) {
        return -6;
    }
    gquic_str_init(&identity->label);
    gquic_str_copy(&identity->label, &(*sess)->sess_ticket);
    identity->obfuscated_ticket_age = ticket_age + (*sess)->age_add;
    gquic_list_insert_before(&hello->psk_identities, identity);


    return 0;
}

int gquic_tls_conn_set_alt_record(gquic_tls_conn_t *const conn) {
    if (conn == NULL || conn->cfg == NULL) {
        return -1;
    }
    conn->in.set_key_self = conn->cfg->alt_record.self;
    conn->in.set_key = conn->cfg->alt_record.set_rkey;
    conn->out.set_key_self = conn->cfg->alt_record.self;
    conn->out.set_key = conn->cfg->alt_record.set_wkey;
    return 0;
}

int gquic_tls_conn_read_handshake(void **const msg, gquic_tls_conn_t *const conn) {
    int ret = 0;
    gquic_str_t data = { 0, NULL };
    if (msg == NULL || conn == NULL) {
        return -1;
    }
    if (conn->cfg->alt_record.read_handshake_msg == NULL
        || conn->cfg->alt_record.read_handshake_msg(&data, conn->cfg->alt_record.self) != 0) {
        return -2;
    }
    if (GQUIC_STR_SIZE(&data) == 0) {
        return -3;
    }
    
    switch (GQUIC_STR_FIRST_BYTE(&data)) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ:
        if ((*msg = gquic_tls_hello_req_msg_alloc()) == NULL) {
            ret = -3;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO:
        if ((*msg = gquic_tls_client_hello_msg_alloc()) == NULL) {
            ret = -4;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO:
        if ((*msg = gquic_tls_server_hello_msg_alloc()) == NULL) {
            ret = -5;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if ((*msg = gquic_tls_new_sess_ticket_msg_alloc()) == NULL) {
                ret = -6;
                goto failure;
            }
        }
        else {
            ret = -7;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if ((*msg = gquic_tls_cert_msg_alloc()) == NULL) {
                ret = -8;
                goto failure;
            }
        }
        else {
            ret = -9;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ:
        if (conn->ver == GQUIC_TLS_VERSION_13) {
            if ((*msg = gquic_tls_cert_req_msg_alloc()) == NULL) {
                ret = -10;
                goto failure;
            }
        }
        else {
            ret = -11;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS:
        if ((*msg = gquic_tls_cert_status_msg_alloc()) == NULL) {
            ret = -12;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE:
        if ((*msg = gquic_tls_server_key_exchange_msg_alloc()) == NULL) {
            ret = -13;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE:
        if ((*msg = gquic_tls_server_hello_done_msg_alloc()) == NULL) {
            ret = -14;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE:
        if ((*msg = gquic_tls_client_key_exchange_msg_alloc()) == NULL) {
            ret = -15;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY:
        if ((*msg = gquic_tls_cert_verify_msg_alloc()) == NULL) {
            ret = -16;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO:
        if ((*msg = gquic_tls_next_proto_msg_alloc()) == NULL) {
            ret = -17;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED:
        if ((*msg = gquic_tls_finished_msg_alloc()) == NULL) {
            ret = -18;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS:
        if ((*msg = gquic_tls_encrypt_ext_msg_alloc()) == NULL) {
            ret = -19;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA:
        if ((*msg = gquic_tls_end_of_early_data_msg_alloc()) == NULL) {
            ret = -20;
            goto failure;
        }
        break;
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE:
        if ((*msg = gquic_tls_key_update_msg_alloc()) == NULL) {
            ret = -21;
            goto failure;
        }
        break;
    default:
        ret = -22;
        goto failure;
    }
    GQUIC_TLS_MSG_INIT(*msg);
    gquic_reader_str_t reader = data;
    if ((ret = GQUIC_TLS_MSG_DESERIALIZE(*msg, &reader)) != 0) {
        return -23;
    }

    gquic_str_reset(&data);
    return 0;
failure:
    gquic_str_reset(&data);
    return ret;
}

static int gquic_tls_conn_cli_sess_cache_key(gquic_str_t *const ret, const gquic_net_addr_t *const addr, const gquic_tls_config_t *const cfg) {
    if (ret == NULL || addr == NULL || cfg == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&cfg->ser_name) > 0) {
        return gquic_str_copy(ret, &cfg->ser_name);
    }
    return gquic_net_addr_to_str(addr, ret);
}

static int gquic_compare_now_asn1_time(const ASN1_TIME *const ref_time) {
    int cmp;
    ASN1_TIME *cur = ASN1_TIME_new();
    ASN1_TIME_set(cur, time(NULL));
    cmp = ASN1_TIME_compare(cur, ref_time);
    ASN1_TIME_free(cur);
    return cmp;
}

static int gquic_equal_common_name(const gquic_str_t *const n1, X509_NAME *const n2) {
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

int gquic_tls_conn_write_record(size_t *writed_size, gquic_tls_conn_t *const conn, u_int8_t record_type, const gquic_str_t *const data) {
    if (conn == NULL || data == NULL) {
        return -1;
    }
    *writed_size = 0;
    if (conn->cfg->alt_record.write_record != NULL) {
        if (record_type == GQUIC_TLS_RECORD_TYPE_CHANGE_CIPHER_SEPC) {
            *writed_size = GQUIC_STR_SIZE(data);
            return 0;
        }
        return conn->cfg->alt_record.write_record(writed_size, conn->cfg->alt_record.self, data);
    }
    return -2;
}

int gquic_tls_conn_write_max_write_size(size_t *const ret, const gquic_tls_conn_t *const conn, const u_int8_t record_type) {
    if (ret == NULL || conn == NULL || conn->cfg == NULL) {
        return -1;
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
        return -2;
    }
    if (conn->sent_pkg_count >= 1000) {
        *ret = GQUIC_MAX_PLAINTEXT;
        return 0;
    }
    *ret = payload_size * (conn->sent_pkg_count + 1);
    if (*ret > GQUIC_MAX_PLAINTEXT) {
        *ret = GQUIC_MAX_PLAINTEXT;
    }
    return 0;
}

int gquic_tls_conn_send_alert(gquic_tls_conn_t *const conn, u_int8_t alert) {
    if (conn == NULL) {
        return -1;
    }
    if (conn->cfg->alt_record.send_alert == NULL) {
        return -2;
    }
    return conn->cfg->alt_record.send_alert(conn->cfg->alt_record.self, alert);
}

static int gquic_tls_half_conn_inc_seq(gquic_tls_half_conn_t *const half_conn) {
    if (half_conn == NULL) {
        return -1;
    }
    size_t i;
    for (i = 7; i >= 0; i++) {
        if (++((unsigned char *) GQUIC_STR_VAL(&half_conn->seq))[i] != 0) {
            return 0;
        }
    }

    return -2;
}

int gquic_tls_conn_verify_ser_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs) {
    gquic_str_t *cert;
    int first = 1;
    if (conn == NULL || certs == NULL) {
        return -1;
    }
    if (gquic_list_head_init(&conn->peer_certs) != 0) {
        return -2;
    }

    GQUIC_LIST_FOREACH(cert, certs) {
        const u_int8_t *cert_cnt = GQUIC_STR_VAL(cert);
        X509 *x509 = d2i_X509(NULL, &cert_cnt, GQUIC_STR_SIZE(cert));
        if (x509 == NULL) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
            return -3;
        }
        if (first) {
            int pubkey_id = EVP_PKEY_id(X509_get_pubkey(x509));
            if (pubkey_id != EVP_PKEY_RSA
                && pubkey_id != EVP_PKEY_EC
                && pubkey_id != EVP_PKEY_ED25519) {
                gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
                return -4;
            }
            first = 0;
        }
        X509_free(x509);
        gquic_str_t *peer_cert = gquic_list_alloc(sizeof(gquic_str_t));
        if (peer_cert == NULL) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            return -5;
        }
        if (gquic_str_copy(peer_cert, cert) != 0) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            return -6;
        }
        if (gquic_list_insert_before(&conn->peer_certs, peer_cert) != 0) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_INTERNAL_ERROR);
            return -7;
        }
    }
    if (conn->cfg->verify_peer_certs != NULL) {
        if (conn->cfg->verify_peer_certs(&conn->peer_certs, &conn->verified_chains) != 0) {
            gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_BAD_CERT);
            return -8;
        }
    }

    return 0;
}

int gquic_tls_conn_handshake(gquic_tls_conn_t *const conn) {
    int ret;
    if (conn == NULL) {
        return -1;
    }
    sem_wait(&conn->handshake_mtx);
    if (conn->is_client) {
        if ((ret = gquic_tls_client_handshake(conn)) != 0) {
            return -2;
        }
    }
    else {
        if ((ret = gquic_tls_server_handshake(conn)) != 0) {
            return -3;
        }
    }
    conn->handshakes++;
    sem_post(&conn->handshake_mtx);
    return 0;
}

int gquic_tls_conn_get_sess_ticket(gquic_str_t *const msg, gquic_tls_conn_t *const conn) {
    int ret = 0;
    gquic_tls_sess_state_t state;
    gquic_str_t *peer_cert = NULL;
    gquic_str_t *cert = NULL;
    gquic_tls_new_sess_ticket_msg_t *ticket = NULL;
    if (msg == NULL || conn == NULL) {
        return -1;
    }
    if (conn->is_client || conn->handshake_status != 1 || conn->cfg->alt_record.self == NULL) {
        return -2;
    }
    if (conn->cfg->sess_ticket_disabled) {
        return 0;
    }
    if ((ticket = gquic_tls_new_sess_ticket_msg_alloc()) == NULL) {
        return -3;
    }
    GQUIC_TLS_MSG_INIT(ticket);
    gquic_tls_sess_state_init(&state);
    GQUIC_LIST_FOREACH(peer_cert, &conn->peer_certs) {
        if ((cert = gquic_list_alloc(sizeof(gquic_str_t *))) == NULL) {
            return -4;
        }
        gquic_str_init(cert);
        if (gquic_str_copy(cert, peer_cert) != 0) {
            return -5;
        }
        if (gquic_list_insert_before(&state.cert.certs, cert) != 0) {
            return -6;
        }
    }
    // TODO copy ocsp and scts
    state.cipher_suite = conn->cipher_suite;
    if (gquic_str_copy(&state.resumption_sec, &conn->resumption_sec) != 0) {
        return -7;
    }
    state.create_at = time(NULL);

    if (gquic_str_alloc(&ticket->label, gquic_tls_sess_state_size(&state)) != 0) {
        ret = -8;
        goto failure;
    }
    gquic_writer_str_t writer = ticket->label;
    if (gquic_tls_sess_state_serialize(&state, &writer) != 0) {
        ret = -9;
        goto failure;
    }
    ticket->lifetime = 7 * 24 * 60;
    if (gquic_tls_msg_combine_serialize(msg, ticket) != 0) {
        ret = -10;
        goto failure;
    }
    gquic_tls_msg_release(ticket);
    return 0;
failure:
    gquic_tls_msg_release(ticket);
    return ret;
}

int gquic_tls_conn_encrypt_ticket(gquic_str_t *const encrypted, gquic_tls_conn_t *const conn, const gquic_str_t *const state) {
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX *hmac = NULL;
    int size = 0;
    gquic_tls_ticket_key_t *key = NULL;
    if (encrypted == NULL || conn == NULL || state == NULL) {
        return -1;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        return -2;
    }
    if (EVP_CIPHER_CTX_init(ctx) <= 0) {
        ret = -3;
        goto failure;
    }
    if ((hmac = HMAC_CTX_new()) == NULL) {
        ret = -4;
        goto failure;
    }
    if (gquic_str_alloc(encrypted, 16 + 16 + GQUIC_STR_SIZE(state) + 32) != 0) {
        ret = -5;
        goto failure;
    }
    if (RAND_bytes(GQUIC_STR_VAL(encrypted) + 16, 16) <= 0) {
        ret = -6;
        goto failure;
    }
    key = GQUIC_LIST_FIRST(&conn->cfg->sess_ticket_keys);
    memcpy(GQUIC_STR_VAL(encrypted), key->name, 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->aes_key, GQUIC_STR_VAL(encrypted) + 16) <= 0) {
        ret = -7;
        goto failure;
    }
    if (EVP_EncryptUpdate(ctx, GQUIC_STR_VAL(encrypted) + 16 + 16, &size, GQUIC_STR_VAL(state), GQUIC_STR_SIZE(state)) <= 0) {
        ret = -8;
        goto failure;
    }
    if (EVP_EncryptFinal_ex(ctx, GQUIC_STR_VAL(encrypted) + 16 + 16 + size, &size) <= 0) {
        ret = -9;
        goto failure;
    }
    if (HMAC_Init_ex(hmac, key->hmac_key, 16, EVP_sha256(), NULL) <= 0) {
        ret = -10;
        goto failure;
    }
    if (HMAC_Update(hmac, GQUIC_STR_VAL(encrypted), GQUIC_STR_SIZE(encrypted) - 32) <= 0) {
        ret = -11;
        goto failure;
    }
    if (HMAC_Final(hmac, GQUIC_STR_VAL(encrypted) + GQUIC_STR_SIZE(encrypted) - 32, (u_int32_t *) &size) <= 0) {
        ret = -12;
        goto failure;
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    return 0;
failure:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    return ret;
}

int gquic_tls_conn_decrypt_ticket(gquic_str_t *const plain,
                                  int *const is_oldkey,
                                  gquic_tls_conn_t *const conn,
                                  const gquic_str_t *const encrypted) {
    int ret = 0;
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
        return -1;
    }
    if (GQUIC_STR_SIZE(encrypted) < 16 + 16 + 32) {
        return -2;
    }
    if ((hmac = HMAC_CTX_new()) == NULL) {
        return -3;
    }
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = -4;
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
        *is_oldkey = 0;
        return 0;
    }
    if (HMAC_Init_ex(hmac, key->hmac_key, 16, EVP_sha256(), NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if (HMAC_Update(hmac, GQUIC_STR_VAL(encrypted), GQUIC_STR_SIZE(encrypted) - 32) <= 0) {
        ret = -6;
        goto failure;
    }
    if (HMAC_Final(hmac, mac_cnt, &size) <= 0) {
        ret = -7;
        goto failure;
    }
    if (gquic_str_cmp(&mac_expect, &mac) != 0) {
        *is_oldkey = 0;
        return 0;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key->aes_key, GQUIC_STR_VAL(&iv)) <= 0) {
        ret = -8;
        goto failure;
    }
    if (gquic_str_alloc(plain, GQUIC_STR_SIZE(&cipher_text)) != 0) {
        ret = -9;
        goto failure;
    }
    if (EVP_DecryptUpdate(ctx, GQUIC_STR_VAL(plain), (int *) &size, GQUIC_STR_VAL(&cipher_text), GQUIC_STR_SIZE(&cipher_text)) != 0) {
        ret = -10;
        goto failure;
    }
    if (EVP_DecryptFinal_ex(ctx, GQUIC_STR_VAL(plain) + size, (int *) &size) <= 0) {
        ret = -11;
        goto failure;
    }
    *is_oldkey = 1;

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    return 0;
failure:
    *is_oldkey = 0;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (hmac != NULL) {
        HMAC_CTX_free(hmac);
    }
    return ret;
}

int gquic_tls_conn_handle_post_handshake_msg(gquic_tls_conn_t *const conn) {
    void *msg = NULL;
    if (conn == NULL) {
        return -1;
    }

    if (gquic_tls_conn_read_handshake(&msg, conn) != 0) {
        return -2;
    }

    switch (GQUIC_TLS_MSG_META(msg).type) {
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET:
        // TODO
    case GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE:
        // TODO
    default:
        gquic_tls_conn_send_alert(conn, GQUIC_TLS_ALERT_UNEXPECTED_MESSAGE);
    }

    gquic_tls_msg_release(msg);
    return 0;
}

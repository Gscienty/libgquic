#include "tls/conn.h"
#include <openssl/x509.h>
#include <openssl/pem.h>

static int gquic_tls_conn_cli_sess_cache_key(gquic_str_t *const, const gquic_net_addr_t *const, const gquic_tls_config_t *const);

int gquic_tls_conn_init(gquic_tls_conn_t *const conn,
                        const gquic_net_addr_t *const addr,
                        const gquic_tls_config_t *const cfg) {
    if (conn == NULL) {
        return -1;
    }
    conn->addr = addr;
    conn->cfg = cfg;
    conn->is_client = 0;
    conn->handshake_status = 0;
    conn->ver = 0;
    conn->cipher_suite = 0;
    gquic_str_init(&conn->ocsp_resp);
    gquic_list_head_init(&conn->scts);
    return 0;
}

int gquic_tls_conn_load_session(const gquic_tls_conn_t *const conn,
                                gquic_str_t *const cache_key,
                                gquic_tls_client_sess_state_t **const sess,
                                gquic_str_t *const early_sec,
                                gquic_str_t *const binder_key,
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
    if ((*(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&hello->supported_versions))) == GQUIC_TLS_VERSION_13) {
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
    if (conn->cfg->cli_sess_cache->get_fptr(sess, cache_key) != 0 && *sess == NULL) {
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
        if (gquic_list_head_empty(&(*sess)->verified_chain)) {
            return 0;
        }
        if (gquic_list_head_empty(&(*sess)->ser_certs)) {
            return -4;
        }
        gquic_str_t *ser_cert = gquic_list_next(GQUIC_LIST_PAYLOAD(&(*sess)->ser_certs));
        X509 *x509_ser_cert = d2i_X509(NULL, (unsigned char const **) &GQUIC_STR_VAL(ser_cert), GQUIC_STR_SIZE(ser_cert));
        ASN1_TIME *ser_cert_not_after = X509_get_notAfter(x509_ser_cert);
        ASN1_TIME *cfg_cur = ASN1_TIME_new();
        ASN1_TIME_set(cfg_cur, time(NULL));
        int cmp = ASN1_TIME_compare(cfg_cur, ser_cert_not_after);
        ASN1_TIME_free(cfg_cur);
        if (cmp == 1) {
            X509_free(x509_ser_cert);
            return 0;
        }
        else if (cmp == -2) {
            X509_free(x509_ser_cert);
            return -5;
        }

        X509_NAME *name = X509_get_subject_name(x509_ser_cert);
        gquic_str_t ser_cert_common_name;
        int ret = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);
        if (gquic_str_alloc(&ser_cert_common_name, ret) != 0) {
            X509_free(x509_ser_cert);
            return -6;
        }
        ret = X509_NAME_get_text_by_NID(name,
                                        NID_commonName,
                                        GQUIC_STR_VAL(&ser_cert_common_name),
                                        GQUIC_STR_SIZE(&ser_cert_common_name));
        X509_free(x509_ser_cert);

        // TODO
    }

    return 0;
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


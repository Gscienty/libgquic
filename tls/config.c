#include <openssl/sha.h>
#include <string.h>
#include "tls/config.h"
#include "tls/common.h"

static u_int16_t __supported_versions[] = {
    /*GQUIC_TLS_VERSION_10,*/
    /*GQUIC_TLS_VERSION_11,*/
    /*GQUIC_TLS_VERSION_12,*/
    GQUIC_TLS_VERSION_13
};

int gquic_tls_record_layer_init(gquic_tls_record_layer_t *const record_layer) {
    if (record_layer == NULL) {
        return -1;
    }
    record_layer->self = NULL;
    record_layer->set_rkey = NULL;
    record_layer->set_wkey = NULL;
    record_layer->read_handshake_msg = NULL;
    record_layer->write_record = NULL;
    record_layer->send_alert = NULL;
    record_layer->release = NULL;
    return 0;
}

int gquic_tls_config_init(gquic_tls_config_t *const cfg) {
    if (cfg == NULL) {
        return -1;
    }

    cfg->epoch = 0;
    gquic_list_head_init(&cfg->certs);
    gquic_rbtree_root_init(&cfg->map_certs);
    gquic_str_init(&cfg->cli_ca);
    gquic_str_init(&cfg->ser_ca);
    gquic_list_head_init(&cfg->next_protos);
    gquic_str_init(&cfg->ser_name);
    cfg->insecure_skiy_verify = 0;
    gquic_list_head_init(&cfg->cipher_suites);
    cfg->ser_perfer_cipher_suite = 0;
    cfg->sess_ticket_disabled = 0;
    memset(cfg->sess_ticket_key, 0, sizeof(cfg->sess_ticket_key));
    cfg->min_v = 0;
    cfg->max_v = 0;
    cfg->dynamic_record_sizing_disabled = 0;
    gquic_list_head_init(&cfg->sess_ticket_keys);
    cfg->renegotiation = 0;
    gquic_list_head_init(&cfg->curve_perfers);
    cfg->cli_sess_cache = NULL;
    cfg->extensions = NULL;
    cfg->received_extensions = NULL;
    cfg->verify_peer_certs = NULL;
    gquic_tls_record_layer_init(&cfg->alt_record);
    cfg->enforce_next_proto_selection = 0;

    return 0;
}

static int empty_config_inited = 0;
static gquic_tls_config_t empty_config;

int gquic_tls_config_default(gquic_tls_config_t **const cfg) {
    if (cfg == NULL) {
        return -1;
    }
    if (!empty_config_inited) {
        gquic_tls_config_init(&empty_config);
        empty_config_inited = 1;
    }
    *cfg = &empty_config;

    return 0;
}

int gquic_tls_ticket_key_deserialize(gquic_tls_ticket_key_t *ticket_key, const void *buf, const size_t size) {
    if (ticket_key == NULL || buf == NULL) {
        return -1;
    }
    if (size != 32) {
        return -2;
    }
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, buf, size);
    SHA256_Final(hash, &sha);
    memcpy(ticket_key->name, hash, 16);
    memcpy(ticket_key->aes_key, hash + 16, 16);
    memcpy(ticket_key->hmac_key, hash + 32, 16);
    return 0;
}

int gquic_tls_config_supported_versions(gquic_list_t *ret, const gquic_tls_config_t *cfg, int is_client) {
    if (ret == NULL) {
        return -1;
    }
    gquic_list_head_init(ret);
    size_t versions_count = sizeof(__supported_versions) / sizeof(u_int16_t);
    size_t i;
    for (i = 0; i < versions_count; i++) {
        if (((cfg == NULL || cfg->min_v == 0) && __supported_versions[i] < GQUIC_TLS_VERSION_10)
            || (cfg != NULL && cfg->min_v != 0 && __supported_versions[i] < cfg->min_v)
            || (cfg != NULL && cfg->max_v != 0 && __supported_versions[i] > cfg->max_v)
            || (is_client && __supported_versions[i] < GQUIC_TLS_VERSION_10)) {
            continue;
        }
        u_int16_t *field = gquic_list_alloc(sizeof(u_int16_t));
        if (field == NULL) {
            return -2;
        }
        gquic_list_insert_before(ret, field);
        *field = __supported_versions[i];
    }

    return 0;
}

static u_int16_t __default_curve_preferences[] = {
    GQUIC_TLS_CURVE_X25519,
    /*GQUIC_TLS_CURVE_P256,*/
    /*GQUIC_TLS_CURVE_P384,*/
    /*GQUIC_TLS_CURVE_P521*/
};

int gquic_tls_config_curve_preferences(gquic_list_t *ret) {
    if (ret == NULL) {
        return -1;
    }
    if (gquic_list_head_init(ret) != 0) {
        return -2;
    }
    size_t i;
    u_int16_t *payload;
    for (i = 0; i < sizeof(__default_curve_preferences) / sizeof(u_int16_t); i++) {
        if ((payload = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
            return -3;
        }
        *payload = __default_curve_preferences[i];
        if (gquic_list_insert_before(ret, payload) != 0) {
            return -4;
        }
    }
    return 0;
}

int gquic_tls_sig_trans(u_int8_t *const sig, const u_int16_t sigsche) {
    if (sig == NULL) {
        return -1;
    }
    switch (sigsche) {
    case GQUIC_SIGALG_PKCS1_SHA1:
    case GQUIC_SIGALG_PKCS1_SHA256:
    case GQUIC_SIGALG_PKCS1_SHA384:
    case GQUIC_SIGALG_PKCS1_SHA512:
        *sig = GQUIC_SIG_PKCS1V15;
        break;
    case GQUIC_SIGALG_PSS_SHA256:
    case GQUIC_SIGALG_PSS_SHA384:
    case GQUIC_SIGALG_PSS_SHA512:
        *sig = GQUIC_SIG_RSAPSS;
        break;
    case GQUIC_SIGALG_ECDSA_SHA1:
    case GQUIC_SIGALG_ECDSA_P256_SHA256:
    case GQUIC_SIGALG_ECDSA_P384_SHA384:
    case GQUIC_SIGALG_ECDSA_P512_SHA512:
        *sig = GQUIC_SIG_ECDSA;
        break;
    case GQUIC_SIGALG_ED25519:
        *sig = GQUIC_SIG_ED25519;
        break;
    default:
        return -2;
    }
    return 0;
}

static u_int16_t __supported_sigalgs_tls12[] = {
    GQUIC_SIGALG_PKCS1_SHA256,
    GQUIC_SIGALG_ECDSA_P256_SHA256,
    GQUIC_SIGALG_ED25519,
    GQUIC_SIGALG_PKCS1_SHA384,
    GQUIC_SIGALG_PKCS1_SHA512,
    GQUIC_SIGALG_ECDSA_P384_SHA384,
    GQUIC_SIGALG_ECDSA_P512_SHA512,
    GQUIC_SIGALG_PKCS1_SHA1,
    GQUIC_SIGALG_ECDSA_SHA1
};

int gquic_tls_supported_sigalgs_tls12(gquic_list_t *const sigsches) {
    size_t i;
    u_int16_t *payload;
    if (sigsches == NULL) {
        return -1;
    }
    if (gquic_list_head_init(sigsches) != 0) {
        return -2;
    }
    for (i = 0; i < sizeof(__supported_sigalgs_tls12) / sizeof(u_int16_t); i++) {
        if ((payload = gquic_list_alloc(sizeof(u_int16_t))) == NULL) {
            return -3;
        }
        *payload = __supported_sigalgs_tls12[i];
        if (gquic_list_insert_before(sigsches, payload) != 0) {
            return -4;
        }
    }

    return 0;
}

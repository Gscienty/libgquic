#include <openssl/sha.h>
#include <string.h>
#include "tls/config.h"

static u_int16_t __supported_versions[] = {
    GQUIC_TLS_VERSION_10,
    GQUIC_TLS_VERSION_11,
    GQUIC_TLS_VERSION_12,
    GQUIC_TLS_VERSION_13
};

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

static gquic_curve_id_t __default_curve_preferences[] = {
    GQUIC_TLS_CURVE_X25519,
    GQUIC_TLS_CURVE_P256,
    GQUIC_TLS_CURVE_P384,
    GQUIC_TLS_CURVE_P521
};

int gquic_tls_config_curve_preferences(gquic_list_t *ret) {
    if (ret == NULL) {
        return -1;
    }
    if (gquic_list_head_init(ret) != 0) {
        return -2;
    }
    size_t count = sizeof(__default_curve_preferences) / sizeof(gquic_curve_id_t);
    size_t i;
    for (i = 0; i < count; i++) {
        gquic_curve_id_t *field = gquic_list_alloc(sizeof(gquic_curve_id_t));
        if (field == NULL) {
            return -3;
        }
        *field = __default_curve_preferences[i];
        if (gquic_list_insert_before(ret, field) != 0) {
            return -4;
        }
    }
    return 0;
}

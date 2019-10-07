#include "tls/handshake_client.h"
#include "tls/config.h"
#include "tls/key_schedule.h"
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

int gquic_tls_handshake_client_hello_init(gquic_tls_client_hello_msg_t *msg, const gquic_tls_conn_t *conn) {
    gquic_str_t *proto;
    size_t next_protos_len = 0;
    gquic_list_t supported_versions;
    u_int16_t client_hello_version;
    int ret = 0;
    size_t count;
    size_t i;

    if (msg == NULL || conn == NULL) {
        return -1;
    }
    if (gquic_list_head_init(&supported_versions) != 0) {
        return -2;
    }
    if (gquic_tls_client_hello_msg_init(msg) != 0) {
        ret = -3;
        goto failure;
    }

    if (GQUIC_STR_SIZE(&conn->cfg->ser_name) == 0 && !conn->cfg->insecure_skiy_verify) {
        ret = -4;
        goto failure;
    }
    GQUIC_LIST_FOREACH(proto, &conn->cfg->next_protos) {
        if (proto->size == 0 || proto->size > 255) {
            ret = -5;
            goto failure;
        }
        next_protos_len += proto->size;
    }
    if (next_protos_len > 0xffff) {
        ret = -6;
        goto failure;
    }
    if (gquic_tls_config_supported_versions(&supported_versions, conn->cfg, 1) != 0) {
        ret = -7;
        goto failure;
    }
    if (gquic_list_head_empty(&supported_versions)) {
        ret = -8;
        goto failure;
    }
    client_hello_version = *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_versions));
    if (client_hello_version > GQUIC_TLS_VERSION_12) {
        client_hello_version = GQUIC_TLS_VERSION_12;
    }

    msg->vers = client_hello_version;
    if (gquic_str_alloc(&msg->compression_methods, 1) != 0) {
        ret = -9;
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&msg->compression_methods) = 0;
    if (gquic_str_alloc(&msg->random, 32) != 0) {
        ret = -10;
        goto failure;
    }
    if (gquic_str_alloc(&msg->sess_id, 32) != 0) {
        ret = -11;
        goto failure;
    }
    msg->ocsp_stapling = 1;
    msg->scts = 1;
    if (gquic_str_copy(&msg->ser_name, &conn->cfg->ser_name) != 0) {
        ret = -12;
        goto failure;
    }
    if (gquic_tls_config_curve_preferences(&msg->supported_curves) != 0) {
        ret = -13;
        goto failure;
    }
    if (gquic_str_alloc(&msg->supported_points, 1) != 0) {
        ret = -14;
        goto failure;
    }
    *(u_int8_t *) GQUIC_STR_VAL(&msg->supported_points) = 0;
    msg->next_proto_neg = !gquic_list_head_empty(&conn->cfg->next_protos);
    msg->secure_regegotiation_supported = 1;
    if (gquic_list_copy(&msg->alpn_protos, &conn->cfg->next_protos, gquic_proto_copy) != 0) {
        ret = -15;
        goto failure;
    }
    if (gquic_list_copy(&msg->supported_versions, &supported_versions, NULL) != 0) {
        ret = -16;
        goto failure;
    }
    count = sizeof(__cipher_suites) / sizeof(int);
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = gquic_list_alloc(sizeof(u_int16_t));
        if (cipher_suite == NULL) {
            ret = -17;
            goto failure;
        }
        *cipher_suite = 0xFFFF & __cipher_suites[i];
        if (gquic_list_insert_before(&msg->cipher_suites, cipher_suite) != 0) {
            ret = -18;
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
                ret = -19;
                goto failure;
            }
            *sigalg = __supported_sign_algos[i];
            if (gquic_list_insert_before(&msg->supported_sign_algos, sigalg) != 0) {
                ret = -20;
                goto failure;
            }
        }
    }

    // TODO

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

int gquic_tls_handshake_client_hello_edch_params_init(gquic_tls_ecdhe_params_t *ret, gquic_tls_client_hello_msg_t *msg) {
    if (ret == NULL || msg == NULL) {
        return -1;
    }
    if (*((u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&msg->supported_versions))) == GQUIC_TLS_VERSION_13) {
        if (gquic_tls_ecdhe_params_generate(ret, GQUIC_TLS_CURVE_X25519) != 0) {
            return -2;
        }
        gquic_tls_key_share_t *ks = gquic_list_alloc(sizeof(gquic_tls_key_share_t));
        if (ks == NULL) {
            gquic_tls_ecdhe_params_release(ret);
            return -3;
        }
        ks->group = GQUIC_TLS_CURVE_X25519;
        gquic_str_init(&ks->data);
        if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(ret, &ks->data) != 0) {
            gquic_tls_ecdhe_params_release(ret);
            gquic_list_release(ks);
            return -4;
        }
    }

    return 0;
}

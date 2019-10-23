#include "tls/key_agreement.h"
#include "tls/key_schedule.h"
#include "tls/client_key_exchange_msg.h"
#include "tls/auth.h"
#include "tls/config.h"
#include "util/big_endian.h"
#include <string.h>
#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/err.h>

static int hash_for_ser_key_exchange(gquic_str_t *const,
                                     const u_int8_t,
                                     const EVP_MD *const,
                                     const u_int16_t,
                                     const gquic_list_t *const);

#define GQUIC_TLS_KEY_AGREEMENT_TYPE_RSA 0x00
#define GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE 0x01

typedef struct gquic_tls_ecdhe_key_agreement_s gquic_tls_ecdhe_key_agreement_t;
struct gquic_tls_ecdhe_key_agreement_s {
    u_int16_t ver;
    int is_rsa;
    gquic_tls_ecdhe_params_t params;

    gquic_tls_client_key_exchange_msg_t ckex_msg;
    gquic_str_t pre_master_sec;
};

static int gquic_tls_ecdhe_key_agreement_init(gquic_tls_ecdhe_key_agreement_t *const);
static int gquic_tls_ecdhe_key_agreement_release(void *const);

static int rsa_ka_process_cli_key_exchange(gquic_str_t *const,
                                           void *const,
                                           const gquic_tls_config_t *const,
                                           const gquic_str_t *const,
                                           const gquic_tls_client_key_exchange_msg_t *const,
                                           u_int16_t);
static int rsa_ka_generate_cli_key_exchange(gquic_str_t *const,
                                            gquic_tls_client_key_exchange_msg_t *const,
                                            void *const,
                                            const gquic_tls_config_t *const,
                                            const gquic_tls_client_hello_msg_t *const,
                                            const gquic_str_t *const);

static int ecdhe_ka_generate_ser_key_exchange(gquic_tls_server_key_exchange_msg_t *const,
                                              void *const,
                                              const gquic_tls_config_t *const,
                                              const gquic_str_t *const,
                                              const gquic_tls_client_hello_msg_t *const,
                                              const gquic_tls_server_hello_msg_t *const);
static int ecdhe_ka_process_cli_key_exchange(gquic_str_t *const,
                                             void *const,
                                             const gquic_tls_config_t *const,
                                             const gquic_str_t *const,
                                             const gquic_tls_client_key_exchange_msg_t *const,
                                             u_int16_t);
static int ecdhe_ka_process_ser_key_exchange(void *const,
                                             const gquic_tls_config_t *const,
                                             const gquic_tls_client_hello_msg_t *const,
                                             const gquic_tls_server_hello_msg_t *const,
                                             const gquic_str_t *const,
                                             const gquic_tls_server_key_exchange_msg_t *const);
static int ecdhe_ka_generate_cli_key_exchange(gquic_str_t *const,
                                              gquic_tls_client_key_exchange_msg_t *const,
                                              void *const,
                                              const gquic_tls_config_t *const,
                                              const gquic_tls_client_hello_msg_t *const,
                                              const gquic_str_t *const);

int gquic_tls_key_agreement_release(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        return -1;
    }
    if (key_agreement->release != NULL) {
        key_agreement->release(key_agreement->self);
    }
    return 0;
}

int gquic_tls_key_agreement_rsa_init(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        return -1;
    }
    key_agreement->type = GQUIC_TLS_KEY_AGREEMENT_TYPE_RSA;
    key_agreement->self = NULL;
    key_agreement->generate_cli_key_exchange = rsa_ka_generate_cli_key_exchange;
    key_agreement->generate_ser_key_exchange = NULL;
    key_agreement->process_cli_key_exchange = rsa_ka_process_cli_key_exchange;
    key_agreement->process_ser_key_exchange = NULL;
    key_agreement->release = NULL;

    return 0;
}

int gquic_tls_key_agreement_ecdhe_init(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        return -1;
    }
    key_agreement->type = GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE;
    key_agreement->self = malloc(sizeof(gquic_tls_ecdhe_key_agreement_t));
    if (key_agreement->self == NULL) {
        return -2;
    }
    gquic_tls_ecdhe_key_agreement_init(key_agreement->self);
    key_agreement->generate_cli_key_exchange = ecdhe_ka_generate_cli_key_exchange;
    key_agreement->generate_ser_key_exchange = ecdhe_ka_generate_ser_key_exchange;
    key_agreement->process_cli_key_exchange = ecdhe_ka_process_cli_key_exchange;
    key_agreement->process_ser_key_exchange = ecdhe_ka_process_ser_key_exchange;
    key_agreement->release = gquic_tls_ecdhe_key_agreement_release;

    return 0;
}

int gquic_tls_key_agreement_ecdhe_set_version(gquic_tls_key_agreement_t *const key_agreement, const u_int16_t ver) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = key_agreement->self;
    if (key_agreement == NULL || key_agreement->self == NULL || key_agreement->type != GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE) {
        return -1;
    }
    ecdhe_self->ver = ver;
    return 0;
}

int gquic_tls_key_agreement_ecdhe_set_is_rsa(gquic_tls_key_agreement_t *const key_agreement, const int is_rsa) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = key_agreement->self;
    if (key_agreement == NULL || key_agreement->self == NULL || key_agreement->type != GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE) {
        return -1;
    }
    ecdhe_self->is_rsa = is_rsa;
    return 0;
}

static int gquic_tls_ecdhe_key_agreement_release(void *const self) {
    if (self == NULL) {
        return -1;
    }
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    gquic_tls_ecdhe_params_release(&ecdhe_self->params);
    gquic_tls_client_key_exchange_msg_reset(&ecdhe_self->ckex_msg);
    gquic_str_reset(&ecdhe_self->pre_master_sec);
    free(self);
    return 0;
}

static int gquic_tls_ecdhe_key_agreement_init(gquic_tls_ecdhe_key_agreement_t *const ka) {
    if (ka == NULL) {
        return -1;
    }
    ka->ver = 0;
    ka->is_rsa = 0;
    gquic_tls_ecdhe_params_init(&ka->params);
    gquic_tls_client_key_exchange_msg_init(&ka->ckex_msg);
    gquic_str_init(&ka->pre_master_sec);
    return 0;
}

static int rsa_ka_process_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                           void *const self,
                                           const gquic_tls_config_t *const cfg,
                                           const gquic_str_t *const p12_d,
                                           const gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                           u_int16_t ver) {
    (void) ver;
    (void) self;
    const gquic_str_t *cipher = &ckex_msg->cipher;
    u_int16_t cipher_len = 0;
    const unsigned char *pkcs_ptr;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret;
    if (pre_master_sec == NULL || cfg == NULL || p12_d == NULL || ckex_msg == NULL) {
        return -1;
    }
    gquic_str_init(pre_master_sec);
    if (GQUIC_STR_SIZE(cipher) <= 2) {
        return -2;
    }
    gquic_big_endian_transfer(&cipher_len, GQUIC_STR_VAL(cipher), 2);
    if (cipher_len != GQUIC_STR_SIZE(cipher) - 2) {
        return -3;
    }
    pkcs_ptr = GQUIC_STR_VAL(p12_d);
    if ((p12 = d2i_PKCS12(NULL, &pkcs_ptr, GQUIC_STR_SIZE(p12_d))) == NULL) {
        return -4;
    }
    if (PKCS12_parse(p12, NULL, &pkey, &cert, NULL) <= 0) {
        ret = -5;
        goto failure;
    }
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        ret = -6;
        goto failure;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        ret = -7;
        goto failure;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ret = -8;
        goto failure;
    }
    if (EVP_PKEY_decrypt(ctx, NULL, &pre_master_sec->size, GQUIC_STR_VAL(cipher) + 2, GQUIC_STR_SIZE(cipher) - 2) <= 0) {
        ret = -9;
        goto failure;
    }
    if (gquic_str_alloc(pre_master_sec, GQUIC_STR_SIZE(pre_master_sec)) != 0) {
        ret = -10;
        goto failure;
    }
    if (EVP_PKEY_decrypt(ctx, GQUIC_STR_VAL(pre_master_sec), &pre_master_sec->size, GQUIC_STR_VAL(cipher) + 2, GQUIC_STR_SIZE(cipher) - 2) <= 0) {
        ret = -9;
        goto failure;
    }

    PKCS12_free(p12);
    EVP_PKEY_CTX_free(ctx);
    return 0;
failure:
    if (p12 != NULL) {
        PKCS12_free(p12);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    gquic_str_reset(pre_master_sec);

    return ret;
}

static int rsa_ka_generate_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                            gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                            void *const self,
                                            const gquic_tls_config_t *const cfg,
                                            const gquic_tls_client_hello_msg_t *const hello,
                                            const gquic_str_t *const cert) {
    (void) self;
    X509 *x509_cert = NULL;
    const unsigned char *cert_ptr = GQUIC_STR_VAL(cert);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t _;
    int ret;
    if (pre_master_sec == NULL || ckex_msg == NULL || cfg == NULL || hello == NULL || cert == NULL) {
        return -1;
    }
    if (gquic_str_alloc(pre_master_sec, 48) != 0) {
        return -2;
    }
    if (gquic_str_init(&ckex_msg->cipher) != 0) {
        ret = -3;
        goto failure;
    }
    gquic_big_endian_transfer(GQUIC_STR_VAL(pre_master_sec), &hello->vers, 2);
    RAND_bytes(GQUIC_STR_VAL(pre_master_sec) + 2, GQUIC_STR_SIZE(pre_master_sec) - 2);
    if ((x509_cert = d2i_X509(NULL, &cert_ptr, GQUIC_STR_SIZE(cert))) == NULL) {
        ret = -4;
        goto failure;
    }
    if ((pkey = X509_get_pubkey(x509_cert)) == NULL) {
        ret = -5;
        goto failure;
    }
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        ret = -6;
        goto failure;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        ret = -7;
        goto failure;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ret = -8;
        goto failure;
    }
    if (EVP_PKEY_encrypt(ctx, NULL, &ckex_msg->cipher.size, GQUIC_STR_VAL(pre_master_sec), GQUIC_STR_SIZE(pre_master_sec)) <= 0) {
        ret = -9;
        goto failure;
    }
    ckex_msg->cipher.size += 2;
    if (gquic_str_alloc(&ckex_msg->cipher, GQUIC_STR_SIZE(&ckex_msg->cipher)) != 0) {
        ret = -10;
        goto failure;
    }
    if (EVP_PKEY_encrypt(ctx, GQUIC_STR_VAL(&ckex_msg->cipher) + 2, &_, GQUIC_STR_VAL(pre_master_sec), GQUIC_STR_SIZE(pre_master_sec)) <= 0) {
        ret = -11;
        goto failure;
    }
    _ = GQUIC_STR_SIZE(&ckex_msg->cipher) - 2;
    gquic_big_endian_transfer(GQUIC_STR_VAL(&ckex_msg->cipher), &_, 2);

    X509_free(x509_cert);
    EVP_PKEY_CTX_free(ctx);
    return 0;
failure:
    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    gquic_str_reset(&ckex_msg->cipher);
    gquic_str_reset(pre_master_sec);
    return ret;
}

static int ecdhe_ka_generate_ser_key_exchange(gquic_tls_server_key_exchange_msg_t *const skex_msg,
                                              void *const self,
                                              const gquic_tls_config_t *const cfg,
                                              const gquic_str_t *const p12_d,
                                              const gquic_tls_client_hello_msg_t *const c_hello,
                                              const gquic_tls_server_hello_msg_t *const s_hello) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    u_int16_t *cand_curve_id;
    u_int16_t *c_hello_curve_id;
    u_int16_t curve_id = 0;
    int openssl_curve_id = 0;
    gquic_list_t preferred_curs;
    gquic_list_t supported_sign_algos_tls12;
    gquic_list_t slices;
    gquic_str_t pubkey;
    gquic_str_t sign;
    gquic_str_t ser_ecdh_params;
    gquic_str_t sig;
    u_int16_t sigalg;
    u_int8_t sig_type;
    const EVP_MD *hash = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *hash_ctx = NULL;
    PKCS12 *p12 = NULL;
    X509 *cert = NULL;
    const unsigned char *pkcs_ptr = NULL;
    int ret;
    size_t off = 0;
    if (skex_msg == NULL || self == NULL || cfg == NULL || p12_d == NULL || c_hello == NULL || s_hello == NULL) {
        return -1;
    }
    gquic_list_head_init(&supported_sign_algos_tls12);
    gquic_list_head_init(&preferred_curs);
    gquic_list_head_init(&slices);
    gquic_tls_ecdhe_params_init(&ecdhe_self->params);
    gquic_str_init(&pubkey);
    gquic_str_init(&sign);
    gquic_str_init(&ser_ecdh_params);
    gquic_str_init(&sig);
    gquic_tls_config_curve_preferences(&preferred_curs);
    gquic_tls_supported_sigalgs_tls12(&supported_sign_algos_tls12);

    GQUIC_LIST_FOREACH(cand_curve_id, &preferred_curs) {
        GQUIC_LIST_FOREACH(c_hello_curve_id, &c_hello->supported_curves) {
            if (*cand_curve_id == *c_hello_curve_id) {
                curve_id = *c_hello_curve_id;
                goto select_curve_id_end;
            }
        }
    }
select_curve_id_end:
    if (curve_id == 0) {
        ret = -2;
        goto failure;
    }
    if (gquic_tls_ecdhe_params_generate(&ecdhe_self->params, curve_id) != 0) {
        ret = -3;
        goto failure;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_self->params, &pubkey) != 0) {
        ret = -4;
        goto failure;
    }
    if (gquic_str_alloc(&ser_ecdh_params, 1 + 2 + 1 + GQUIC_STR_SIZE(&pubkey)) != 0) {
        ret = -5;
        goto failure;
    }
    ((u_int8_t *) GQUIC_STR_VAL(&ser_ecdh_params))[0] = 3;
    gquic_big_endian_transfer(GQUIC_STR_VAL(&ser_ecdh_params) + 1, &curve_id, 2);
    gquic_big_endian_transfer(GQUIC_STR_VAL(&ser_ecdh_params) + 3, &pubkey.size, 1);
    memcpy(GQUIC_STR_VAL(&ser_ecdh_params) + 4, GQUIC_STR_VAL(&pubkey), GQUIC_STR_SIZE(&pubkey));
    switch (curve_id) {
    case GQUIC_TLS_CURVE_X25519:
        openssl_curve_id = EVP_PKEY_X25519;
        break;
    default:
        ret = -6;
        goto failure;
    }
    pkcs_ptr = GQUIC_STR_VAL(p12_d);
    if ((p12 = d2i_PKCS12(NULL, &pkcs_ptr, GQUIC_STR_SIZE(p12_d))) == NULL) {
        return -7;
    }
    if (PKCS12_parse(p12, NULL, &pkey, &cert, NULL) <= 0) {
        ret = -8;
        goto failure;
    }
    if ((pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        ret = -9;
        goto failure;
    }
    if ((ret = gquic_tls_selected_sigalg(&sigalg, &sig_type, &hash, pkey, &c_hello->supported_sign_algos, &supported_sign_algos_tls12, ecdhe_self->ver)) != 0) {
        ret += -10 * 100;
        goto failure;
    }
    hash_ctx = EVP_MD_CTX_new();
    if (ecdhe_self->is_rsa != (sig_type == GQUIC_SIG_PKCS1V15 || sig_type == GQUIC_SIG_RSAPSS)) {
        ret = -11;
        goto failure;
    }
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &c_hello->random;
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &s_hello->random;
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &ser_ecdh_params;
    if ((ret = hash_for_ser_key_exchange(&sign, sig_type, hash, ecdhe_self->ver, &slices)) != 0) {
        ret += -12 * 100;
        goto failure;
    }
    if (EVP_DigestSignInit(hash_ctx, NULL, hash, NULL, pkey) <= 0) {
        ret = -13;
        goto failure;
    }
    if (EVP_DigestSign(hash_ctx, NULL, &sig.size, GQUIC_STR_VAL(&sign), GQUIC_STR_SIZE(&sign)) <= 0) {
        ret = -14;
        goto failure;
    }
    if (gquic_str_alloc(&sig, GQUIC_STR_SIZE(&sig)) != 0) {
        ret = -15;
        goto failure;
    }
    if (EVP_DigestSign(hash_ctx, GQUIC_STR_VAL(&sig), &sig.size, GQUIC_STR_VAL(&sign), GQUIC_STR_SIZE(&sign)) <= 0) {
        ret = -16;
        goto failure;
    }
    if (gquic_str_init(&skex_msg->key) != 0) {
        ret = -17;
        goto failure;
    }
    if (gquic_str_alloc(&skex_msg->key,
                        GQUIC_STR_SIZE(&ser_ecdh_params)
                        + (ecdhe_self->ver >= GQUIC_TLS_VERSION_12 ? 2 : 0)
                        + 2
                        + GQUIC_STR_SIZE(&sig)) != 0) {
        ret = -18;
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&skex_msg->key), GQUIC_STR_VAL(&ser_ecdh_params), GQUIC_STR_SIZE(&ser_ecdh_params));
    off += GQUIC_STR_SIZE(&ser_ecdh_params);
    if (ecdhe_self->ver >= GQUIC_TLS_VERSION_12) {
        if (gquic_big_endian_transfer(GQUIC_STR_VAL(&skex_msg->key) + off, &sigalg, 2) != 0) {
            ret = -19;
            goto failure;
        }
        off += 2;
    }
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&skex_msg->key) + off, &sig.size, 2) != 0) {
        ret = -20;
        goto failure;
    }
    off += 2;
    memcpy(GQUIC_STR_VAL(&skex_msg->key) + off, GQUIC_STR_VAL(&sig), GQUIC_STR_SIZE(&sig));

    while (!gquic_list_head_empty(&preferred_curs)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&preferred_curs)));
    while (!gquic_list_head_empty(&supported_sign_algos_tls12)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_sign_algos_tls12)));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&slices)));
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sign);
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&sig);
    if (pkey_ctx != NULL) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (hash_ctx != NULL) {
        EVP_MD_CTX_free(hash_ctx);
    }
    if (p12 != NULL) {
        PKCS12_free(p12);
    }
    return 0;
failure:
    while (!gquic_list_head_empty(&preferred_curs)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&preferred_curs)));
    while (!gquic_list_head_empty(&supported_sign_algos_tls12)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&supported_sign_algos_tls12)));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&slices)));
    gquic_tls_ecdhe_params_release(&ecdhe_self->params);
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sign);
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&sig);
    if (pkey_ctx != NULL) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (hash_ctx != NULL) {
        EVP_MD_CTX_free(hash_ctx);
    }
    if (p12 != NULL) {
        PKCS12_free(p12);
    }
    return ret;
}
static int ecdhe_ka_process_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                             void *const self,
                                             const gquic_tls_config_t *const cfg,
                                             const gquic_str_t *const p12_d,
                                             const gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                             u_int16_t ver) {
    (void) ver;
    (void) cfg;
    (void) p12_d;
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    gquic_str_t ciphertext;
    if (pre_master_sec == NULL || self == NULL || ckex_msg == NULL) {
        return -1;
    }
    if (gquic_str_init(&ciphertext) != 0) {
        return -2;
    }
    if (gquic_str_init(pre_master_sec) != 0) {
        return -3;
    }
    if (GQUIC_STR_SIZE(&ckex_msg->cipher) == 0 || *((u_int8_t *) GQUIC_STR_VAL(&ckex_msg->cipher)) != GQUIC_STR_SIZE(&ckex_msg->cipher) - 1) {
        return -4;
    }
    ciphertext.val = GQUIC_STR_VAL(&ckex_msg->cipher) + 1;
    ciphertext.size = GQUIC_STR_SIZE(&ckex_msg->cipher) - 1;
    if (GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_self->params, pre_master_sec, &ciphertext) != 0) {
        return -5;
    }

    return 0;
}

static int ecdhe_ka_process_ser_key_exchange(void *const self,
                                             const gquic_tls_config_t *const cfg,
                                             const gquic_tls_client_hello_msg_t *const c_hello,
                                             const gquic_tls_server_hello_msg_t *const s_hello,
                                             const gquic_str_t *const cert_d,
                                             const gquic_tls_server_key_exchange_msg_t *const skex_msg) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    u_int16_t curve_id = 0;
    gquic_str_t ser_ecdh_params;
    gquic_str_t pubkey;
    gquic_str_t sig;
    gquic_str_t self_pubkey;
    gquic_str_t sign;
    u_int16_t sigalg = 0;
    u_int16_t sig_len = 0;
    u_int8_t sig_type = 0;
    gquic_list_t c_sup_sigalgs;
    gquic_list_t slices;
    const EVP_MD *hash = NULL;
    const EVP_PKEY *cert_pubkey = NULL;
    X509 *cert = NULL;
    int ret = 0;
    if (self == NULL || cfg == NULL || c_hello == NULL || s_hello == NULL || cert_d == NULL || skex_msg == NULL) {
        return -1;
    }
    gquic_tls_client_key_exchange_msg_init(&ecdhe_self->ckex_msg);
    gquic_str_init(&ser_ecdh_params);
    gquic_str_init(&pubkey);
    gquic_str_init(&sig);
    gquic_str_init(&self_pubkey);
    gquic_str_init(&sign);
    gquic_list_head_init(&c_sup_sigalgs);
    gquic_list_head_init(&slices);
    if ((cert = d2i_X509(NULL, (const unsigned char **) &cert_d->val, GQUIC_STR_SIZE(cert_d))) == NULL) {
        return -2;
    }
    cert_pubkey = X509_get_pubkey(cert);
    if (GQUIC_STR_SIZE(&skex_msg->key) < 4) {
        return -3;
    }
    if (*((u_int8_t *) GQUIC_STR_VAL(&skex_msg->key)) != 3) {
        return -4;
    }
    if (gquic_big_endian_transfer(&curve_id, GQUIC_STR_VAL(&skex_msg->key) + 1, 2) != 0) {
        return -5;
    }
    pubkey.size = *(unsigned char *) (GQUIC_STR_VAL(&skex_msg->key) + 3);
    if (GQUIC_STR_SIZE(&pubkey) + 4 > GQUIC_STR_SIZE(&skex_msg->key)) {
        return -6;
    }
    if (gquic_str_alloc(&ser_ecdh_params, GQUIC_STR_SIZE(&pubkey) + 4) != 0) {
        return -7;
    }
    memcpy(GQUIC_STR_VAL(&ser_ecdh_params), GQUIC_STR_VAL(&skex_msg->key), GQUIC_STR_SIZE(&pubkey) + 4);
    if (gquic_str_alloc(&pubkey, GQUIC_STR_SIZE(&pubkey)) != 0) {
        ret = -8;
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&pubkey), GQUIC_STR_VAL(&ser_ecdh_params) + 4, GQUIC_STR_SIZE(&pubkey));
    sig.size = GQUIC_STR_SIZE(&skex_msg->key) - GQUIC_STR_SIZE(&ser_ecdh_params);
    if (GQUIC_STR_SIZE(&sig) < 2) {
        ret = -9;
        goto failure;
    }
    if (gquic_str_alloc(&sig, GQUIC_STR_SIZE(&sig)) != 0) {
        ret = -10;
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&skex_msg->key) + GQUIC_STR_SIZE(&ser_ecdh_params), GQUIC_STR_SIZE(&sig));
    if (gquic_tls_ecdhe_params_generate(&ecdhe_self->params, curve_id) != 0) {
        ret = -11;
        goto failure;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_self->params, &ecdhe_self->pre_master_sec, &pubkey) != 0) {
        ret = -12;
        goto failure;
    }
    if (GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_self->params, &self_pubkey) != 0) {
        ret = -13;
        goto failure;
    }
    if (gquic_str_alloc(&ecdhe_self->ckex_msg.cipher, 1 + GQUIC_STR_SIZE(&self_pubkey)) != 0) {
        ret = -14;
        goto failure;
    }
    if (gquic_big_endian_transfer(GQUIC_STR_VAL(&ecdhe_self->ckex_msg.cipher), &self_pubkey.size, 1) != 0) {
        ret = -15;
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&ecdhe_self->ckex_msg.cipher) + 1, GQUIC_STR_VAL(&self_pubkey), GQUIC_STR_SIZE(&self_pubkey));

    if (ecdhe_self->ver >= GQUIC_TLS_VERSION_12) {
        if (gquic_big_endian_transfer(&sigalg, GQUIC_STR_VAL(&sig), 2) != 0) {
            ret = -16;
            goto failure;
        }
        memmove(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&sig) + 2, GQUIC_STR_SIZE(&sig) - 2);
        sig.size -= 2;
        if (GQUIC_STR_SIZE(&sig) < 2) {
            ret = -17;
            goto failure;
        }
    }
    gquic_list_insert_after(&c_sup_sigalgs, gquic_list_alloc(sizeof(u_int16_t)));
    *(u_int16_t *) gquic_list_next(GQUIC_LIST_PAYLOAD(&c_sup_sigalgs)) = sigalg;
    if ((ret = gquic_tls_selected_sigalg(&sigalg, &sig_type, &hash, cert_pubkey, &c_sup_sigalgs, &c_hello->supported_sign_algos, ecdhe_self->ver)) != 0) {
        ret += -18 * 10;
        goto failure;
    }
    if (ecdhe_self->is_rsa != (sig_type == GQUIC_SIG_PKCS1V15 || sig_type == GQUIC_SIG_RSAPSS)) {
        ret = -19;
        goto failure;
    }
    if (gquic_big_endian_transfer(&sig_len, GQUIC_STR_VAL(&sig), 2) != 0) {
        ret = -20;
        goto failure;
    }
    if (sig_len + 2 != GQUIC_STR_SIZE(&sig)) {
        ret = -21;
        goto failure;
    }
    memmove(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&sig) + 2, GQUIC_STR_SIZE(&sig) - 2);
    sig.size -= 2;
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &c_hello->random;
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &s_hello->random;
    gquic_list_insert_before(&slices, gquic_list_alloc(sizeof(const gquic_str_t *)));
    *(const gquic_str_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&slices)) = &ser_ecdh_params;
    if (hash_for_ser_key_exchange(&sign, sig_type, hash, ecdhe_self->ver, &slices) != 0) {
        ret = -22;
        goto failure;
    }
    if (gquic_tls_verify_handshake_sign(sig_type, hash, cert_pubkey, &sign, &sig) != 0) {
        ret = -23;
        goto failure;
    }
    
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sig);
    gquic_str_reset(&self_pubkey);
    while (!gquic_list_head_empty(&c_sup_sigalgs)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&c_sup_sigalgs)));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&slices)));
    if (cert != NULL) {
        X509_free(cert);
    }
    return 0;
failure:
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sig);
    gquic_str_reset(&self_pubkey);
    gquic_str_reset(&ecdhe_self->pre_master_sec);
    while (!gquic_list_head_empty(&c_sup_sigalgs)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&c_sup_sigalgs)));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(gquic_list_next(GQUIC_LIST_PAYLOAD(&slices)));
    gquic_tls_ecdhe_params_release(&ecdhe_self->params);
    if (cert != NULL) {
        X509_free(cert);
    }
    return ret;
}

static int ecdhe_ka_generate_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                              gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                              void *const self,
                                              const gquic_tls_config_t *const cfg,
                                              const gquic_tls_client_hello_msg_t *const c_hello,
                                              const gquic_str_t *const cert) {
    (void) cfg;
    (void) c_hello;
    (void) cert;
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    if (pre_master_sec == NULL || ckex_msg == NULL || self == NULL) {
        return -1;
    }
    gquic_str_init(pre_master_sec);
    gquic_tls_client_key_exchange_msg_init(ckex_msg);
    gquic_str_copy(pre_master_sec, &ecdhe_self->pre_master_sec);
    gquic_str_copy(&ckex_msg->cipher, &ecdhe_self->ckex_msg.cipher);
    return 0;
}

static int hash_for_ser_key_exchange(gquic_str_t *const ret,
                                     const u_int8_t sig_type,
                                     const EVP_MD *const hash,
                                     const u_int16_t ver,
                                     const gquic_list_t *const slices) {
    if (ret == NULL || slices == NULL) {
        return -1;
    }
    if (gquic_str_init(ret) != 0) {
        return -2;
    }
    size_t slices_size = 0;
    gquic_str_t **slice;
    gquic_str_t mid;
    gquic_str_init(&mid);
    gquic_str_init(ret);
    GQUIC_LIST_FOREACH(slice, slices){ slices_size += GQUIC_STR_SIZE(*slice); }
    if (gquic_str_alloc(&mid, slices_size) != 0) {
        return -3;
    }
    slices_size = 0;
    GQUIC_LIST_FOREACH(slice, slices) {
        memcpy(GQUIC_STR_VAL(&mid) + slices_size, GQUIC_STR_VAL(*slice), GQUIC_STR_SIZE(*slice));
        slices_size += GQUIC_STR_SIZE(*slice);
    }
    if (sig_type == GQUIC_SIG_ED25519) {
        if (gquic_str_copy(ret, &mid) != 0) {
            gquic_str_reset(&mid);
            return -4;
        }
        gquic_str_reset(&mid);
        return 0;
    }
    if (ver >= GQUIC_TLS_VERSION_12) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(ctx, hash, NULL) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            return -5;
        }
        if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid)) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            return -6;
        }
        if (gquic_str_alloc(ret, EVP_MD_size(hash)) != 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            return -7;
        }
        if (EVP_DigestFinal_ex(ctx, GQUIC_STR_VAL(ret), NULL) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            return -8;
        }
        gquic_str_reset(&mid);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    if (sig_type == GQUIC_SIG_ECDSA) {
        if (gquic_str_alloc(ret, SHA_DIGEST_LENGTH) != 0) {
            gquic_str_reset(&mid);
            return -9;
        }
        SHA1(GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid), GQUIC_STR_VAL(ret));
        gquic_str_reset(&mid);
        return 0;
    }
    if (gquic_str_alloc(ret, MD5_DIGEST_LENGTH) != 0) {
        gquic_str_reset(&mid);
        return -10;
    }
    MD5(GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid), GQUIC_STR_VAL(ret));
    gquic_str_reset(&mid);
    return 0;
}

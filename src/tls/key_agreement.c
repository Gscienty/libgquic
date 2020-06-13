#include "tls/key_agreement.h"
#include "tls/key_schedule.h"
#include "tls/client_key_exchange_msg.h"
#include "tls/auth.h"
#include "tls/config.h"
#include "tls/meta.h"
#include "util/big_endian.h"
#include "util/malloc.h"
#include "exception.h"
#include <string.h>
#include <openssl/md5.h>
#include <openssl/x509.h>
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

    gquic_tls_client_key_exchange_msg_t *ckex_msg;
    gquic_str_t pre_master_sec;
};

static int gquic_tls_ecdhe_key_agreement_init(gquic_tls_ecdhe_key_agreement_t *const);
static int gquic_tls_ecdhe_key_agreement_dtor(void *const);

static int rsa_ka_process_cli_key_exchange(gquic_str_t *const,
                                           void *const,
                                           const gquic_tls_config_t *const,
                                           PKCS12 *const,
                                           const gquic_tls_client_key_exchange_msg_t *const,
                                           u_int16_t);
static int rsa_ka_generate_cli_key_exchange(gquic_str_t *const,
                                            gquic_tls_client_key_exchange_msg_t *const,
                                            void *const,
                                            const gquic_tls_config_t *const,
                                            const gquic_tls_client_hello_msg_t *const,
                                            X509 *const);

static int ecdhe_ka_generate_ser_key_exchange(gquic_tls_server_key_exchange_msg_t *const,
                                              void *const,
                                              const gquic_tls_config_t *const,
                                              PKCS12 *const,
                                              const gquic_tls_client_hello_msg_t *const,
                                              const gquic_tls_server_hello_msg_t *const);
static int ecdhe_ka_process_cli_key_exchange(gquic_str_t *const,
                                             void *const,
                                             const gquic_tls_config_t *const,
                                             PKCS12 *const,
                                             const gquic_tls_client_key_exchange_msg_t *const,
                                             u_int16_t);
static int ecdhe_ka_process_ser_key_exchange(void *const,
                                             const gquic_tls_config_t *const,
                                             const gquic_tls_client_hello_msg_t *const,
                                             const gquic_tls_server_hello_msg_t *const,
                                             X509 *const,
                                             const gquic_tls_server_key_exchange_msg_t *const);
static int ecdhe_ka_generate_cli_key_exchange(gquic_str_t *const,
                                              gquic_tls_client_key_exchange_msg_t *const,
                                              void *const,
                                              const gquic_tls_config_t *const,
                                              const gquic_tls_client_hello_msg_t *const,
                                              X509 *const);

int gquic_tls_key_agreement_dtor(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (key_agreement->self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (key_agreement->dtor!= NULL) {
        key_agreement->dtor(key_agreement->self);
        gquic_free(key_agreement->self);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_key_agreement_rsa_init(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    key_agreement->type = GQUIC_TLS_KEY_AGREEMENT_TYPE_RSA;
    key_agreement->self = NULL;
    key_agreement->generate_cli_key_exchange = rsa_ka_generate_cli_key_exchange;
    key_agreement->generate_ser_key_exchange = NULL;
    key_agreement->process_cli_key_exchange = rsa_ka_process_cli_key_exchange;
    key_agreement->process_ser_key_exchange = NULL;
    key_agreement->dtor = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_key_agreement_ecdhe_init(gquic_tls_key_agreement_t *const key_agreement) {
    if (key_agreement == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    key_agreement->type = GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE;
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&key_agreement->self, gquic_tls_ecdhe_key_agreement_t));
    gquic_tls_ecdhe_key_agreement_init(key_agreement->self);
    key_agreement->generate_cli_key_exchange = ecdhe_ka_generate_cli_key_exchange;
    key_agreement->generate_ser_key_exchange = ecdhe_ka_generate_ser_key_exchange;
    key_agreement->process_cli_key_exchange = ecdhe_ka_process_cli_key_exchange;
    key_agreement->process_ser_key_exchange = ecdhe_ka_process_ser_key_exchange;
    key_agreement->dtor = gquic_tls_ecdhe_key_agreement_dtor;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_key_agreement_ecdhe_set_version(gquic_tls_key_agreement_t *const key_agreement, const u_int16_t ver) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = key_agreement->self;
    if (key_agreement == NULL || key_agreement->self == NULL || key_agreement->type != GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ecdhe_self->ver = ver;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_key_agreement_ecdhe_set_is_rsa(gquic_tls_key_agreement_t *const key_agreement, const int is_rsa) {
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = key_agreement->self;
    if (key_agreement == NULL || key_agreement->self == NULL || key_agreement->type != GQUIC_TLS_KEY_AGREEMENT_TYPE_ECDHE) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ecdhe_self->is_rsa = is_rsa;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_ecdhe_key_agreement_dtor(void *const self) {
    if (self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    gquic_tls_ecdhe_params_dtor(&ecdhe_self->params);
    gquic_tls_msg_release(ecdhe_self->ckex_msg);
    gquic_str_reset(&ecdhe_self->pre_master_sec);
    gquic_free(self);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_tls_ecdhe_key_agreement_init(gquic_tls_ecdhe_key_agreement_t *const ka) {
    if (ka == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ka->ver = 0;
    ka->is_rsa = 0;
    gquic_tls_ecdhe_params_init(&ka->params);
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_client_key_exchange_msg_alloc(&ka->ckex_msg));
    GQUIC_TLS_MSG_INIT(ka->ckex_msg);
    gquic_str_init(&ka->pre_master_sec);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int rsa_ka_process_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                           void *const self,
                                           const gquic_tls_config_t *const cfg,
                                           PKCS12 *const p12,
                                           const gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                           u_int16_t ver) {
    (void) ver;
    (void) self;
    const gquic_str_t *cipher = &ckex_msg->cipher;
    u_int16_t cipher_len = 0;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int exception = GQUIC_SUCCESS;
    if (pre_master_sec == NULL || cfg == NULL || p12 == NULL || ckex_msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(pre_master_sec);
    if (GQUIC_STR_SIZE(cipher) <= 2) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNSUPPORT_CIPHER_SUITE);
    }
    gquic_big_endian_transfer(&cipher_len, GQUIC_STR_VAL(cipher), 2);
    if (cipher_len != GQUIC_STR_SIZE(cipher) - 2) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if (PKCS12_parse(p12, NULL, &pkey, &cert, NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_BAD_CERT);
        goto failure;
    }
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (EVP_PKEY_decrypt(ctx, NULL, &pre_master_sec->size, GQUIC_STR_VAL(cipher) + 2, GQUIC_STR_SIZE(cipher) - 2) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(pre_master_sec, GQUIC_STR_SIZE(pre_master_sec)))) {
        goto failure;
    }
    if (EVP_PKEY_decrypt(ctx, GQUIC_STR_VAL(pre_master_sec), &pre_master_sec->size, GQUIC_STR_VAL(cipher) + 2, GQUIC_STR_SIZE(cipher) - 2) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DECRYPT_FAILED);
        goto failure;
    }

    EVP_PKEY_CTX_free(ctx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    gquic_str_reset(pre_master_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int rsa_ka_generate_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                            gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                            void *const self,
                                            const gquic_tls_config_t *const cfg,
                                            const gquic_tls_client_hello_msg_t *const hello,
                                            X509 *const x509_cert) {
    (void) self;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t _;
    int exception = GQUIC_SUCCESS;
    if (pre_master_sec == NULL || ckex_msg == NULL || cfg == NULL || hello == NULL || x509_cert == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(pre_master_sec, 48));
    gquic_str_init(&ckex_msg->cipher);
    gquic_big_endian_transfer(GQUIC_STR_VAL(pre_master_sec), &hello->vers, 2);
    RAND_bytes(GQUIC_STR_VAL(pre_master_sec) + 2, GQUIC_STR_SIZE(pre_master_sec) - 2);
    if ((pkey = X509_get_pubkey(x509_cert)) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_BAD_X509);
        goto failure;
    }
    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    if (EVP_PKEY_encrypt(ctx, NULL, &ckex_msg->cipher.size, GQUIC_STR_VAL(pre_master_sec), GQUIC_STR_SIZE(pre_master_sec)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    ckex_msg->cipher.size += 2;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&ckex_msg->cipher, GQUIC_STR_SIZE(&ckex_msg->cipher)))) {
        goto failure;
    }
    if (EVP_PKEY_encrypt(ctx, GQUIC_STR_VAL(&ckex_msg->cipher) + 2, &_, GQUIC_STR_VAL(pre_master_sec), GQUIC_STR_SIZE(pre_master_sec)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ENCRYPT_FAILED);
        goto failure;
    }
    _ = GQUIC_STR_SIZE(&ckex_msg->cipher) - 2;
    gquic_big_endian_transfer(GQUIC_STR_VAL(&ckex_msg->cipher), &_, 2);

    EVP_PKEY_CTX_free(ctx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    gquic_str_reset(&ckex_msg->cipher);
    gquic_str_reset(pre_master_sec);
    GQUIC_PROCESS_DONE(exception);
}

static int ecdhe_ka_generate_ser_key_exchange(gquic_tls_server_key_exchange_msg_t *const skex_msg,
                                              void *const self,
                                              const gquic_tls_config_t *const cfg,
                                              PKCS12 *const p12,
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
    X509 *cert = NULL;
    int exception = GQUIC_SUCCESS;
    size_t off = 0;
    if (skex_msg == NULL || self == NULL || cfg == NULL || p12 == NULL || c_hello == NULL || s_hello == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_CURVE_ID_MACHING_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_generate(&ecdhe_self->params, curve_id))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_self->params, &pubkey))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&ser_ecdh_params, 1 + 2 + 1 + GQUIC_STR_SIZE(&pubkey)))) {
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
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_CURVE_ID_INVALID);
        goto failure;
    }
    if (PKCS12_parse(p12, NULL, &pkey, &cert, NULL) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_BAD_CERT);
        goto failure;
    }
    if ((pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_selected_sigalg(&sigalg, &sig_type,
                                                     &hash, pkey, &c_hello->supported_sign_algos, &supported_sign_algos_tls12, ecdhe_self->ver))) {
        goto failure;
    }
    hash_ctx = EVP_MD_CTX_new();
    if (ecdhe_self->is_rsa != (sig_type == GQUIC_SIG_PKCS1V15 || sig_type == GQUIC_SIG_RSAPSS)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_RSA_SIG_INVALID);
        goto failure;
    }
    const gquic_str_t **tmp = NULL;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &c_hello->random;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &s_hello->random;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &ser_ecdh_params;
    if (GQUIC_ASSERT_CAUSE(exception, hash_for_ser_key_exchange(&sign, sig_type, hash, ecdhe_self->ver, &slices))) {
        goto failure;
    }
    if (EVP_DigestSignInit(hash_ctx, NULL, hash, NULL, pkey) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    if (EVP_DigestSign(hash_ctx, NULL, &sig.size, GQUIC_STR_VAL(&sign), GQUIC_STR_SIZE(&sign)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&sig, GQUIC_STR_SIZE(&sig)))) {
        goto failure;
    }
    if (EVP_DigestSign(hash_ctx, GQUIC_STR_VAL(&sig), &sig.size, GQUIC_STR_VAL(&sign), GQUIC_STR_SIZE(&sign)) <= 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_DIGEST_FAILED);
        goto failure;
    }
    gquic_str_init(&skex_msg->key);
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_str_alloc(&skex_msg->key,
                                           GQUIC_STR_SIZE(&ser_ecdh_params)
                                           + (ecdhe_self->ver >= GQUIC_TLS_VERSION_12 ? 2 : 0)
                                           + 2
                                           + GQUIC_STR_SIZE(&sig)))) {
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&skex_msg->key), GQUIC_STR_VAL(&ser_ecdh_params), GQUIC_STR_SIZE(&ser_ecdh_params));
    off += GQUIC_STR_SIZE(&ser_ecdh_params);
    if (ecdhe_self->ver >= GQUIC_TLS_VERSION_12) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(GQUIC_STR_VAL(&skex_msg->key) + off, &sigalg, 2))) {
            goto failure;
        }
        off += 2;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(GQUIC_STR_VAL(&skex_msg->key) + off, &sig.size, 2))) {
        goto failure;
    }
    off += 2;
    memcpy(GQUIC_STR_VAL(&skex_msg->key) + off, GQUIC_STR_VAL(&sig), GQUIC_STR_SIZE(&sig));

    while (!gquic_list_head_empty(&preferred_curs)) gquic_list_release(GQUIC_LIST_FIRST(&preferred_curs));
    while (!gquic_list_head_empty(&supported_sign_algos_tls12)) gquic_list_release(GQUIC_LIST_FIRST(&supported_sign_algos_tls12));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(GQUIC_LIST_FIRST(&slices));
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    while (!gquic_list_head_empty(&preferred_curs)) gquic_list_release(GQUIC_LIST_FIRST(&preferred_curs));
    while (!gquic_list_head_empty(&supported_sign_algos_tls12)) gquic_list_release(GQUIC_LIST_FIRST(&supported_sign_algos_tls12));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(GQUIC_LIST_FIRST(&slices));
    gquic_tls_ecdhe_params_dtor(&ecdhe_self->params);
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
    GQUIC_PROCESS_DONE(exception);
}
static int ecdhe_ka_process_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                             void *const self,
                                             const gquic_tls_config_t *const cfg,
                                             PKCS12 *const p12_d,
                                             const gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                             u_int16_t ver) {
    (void) ver;
    (void) cfg;
    (void) p12_d;
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    gquic_str_t ciphertext;
    if (pre_master_sec == NULL || self == NULL || ckex_msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&ciphertext);
    gquic_str_init(pre_master_sec);
    if (GQUIC_STR_SIZE(&ckex_msg->cipher) == 0 || GQUIC_STR_FIRST_BYTE(&ckex_msg->cipher) != GQUIC_STR_SIZE(&ckex_msg->cipher) - 1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    ciphertext.val = GQUIC_STR_VAL(&ckex_msg->cipher) + 1;
    ciphertext.size = GQUIC_STR_SIZE(&ckex_msg->cipher) - 1;
    GQUIC_ASSERT_FAST_RETURN(GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_self->params, pre_master_sec, &ciphertext));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int ecdhe_ka_process_ser_key_exchange(void *const self,
                                             const gquic_tls_config_t *const cfg,
                                             const gquic_tls_client_hello_msg_t *const c_hello,
                                             const gquic_tls_server_hello_msg_t *const s_hello,
                                             X509 *const cert,
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
    EVP_PKEY *cert_pubkey = NULL;
    int exception = GQUIC_SUCCESS;
    if (self == NULL || cfg == NULL || c_hello == NULL || s_hello == NULL || cert == NULL || skex_msg == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_TLS_MSG_INIT(ecdhe_self->ckex_msg);
    gquic_str_init(&ser_ecdh_params);
    gquic_str_init(&pubkey);
    gquic_str_init(&sig);
    gquic_str_init(&self_pubkey);
    gquic_str_init(&sign);
    gquic_list_head_init(&c_sup_sigalgs);
    gquic_list_head_init(&slices);
    cert_pubkey = X509_get_pubkey(cert);
    if (GQUIC_STR_SIZE(&skex_msg->key) < 4) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    if (GQUIC_STR_FIRST_BYTE(&skex_msg->key) != 3) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_transfer(&curve_id, GQUIC_STR_VAL(&skex_msg->key) + 1, 2));
    pubkey.size = *(unsigned char *) (GQUIC_STR_VAL(&skex_msg->key) + 3);
    if (GQUIC_STR_SIZE(&pubkey) + 4 > GQUIC_STR_SIZE(&skex_msg->key)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&ser_ecdh_params, GQUIC_STR_SIZE(&pubkey) + 4));
    memcpy(GQUIC_STR_VAL(&ser_ecdh_params), GQUIC_STR_VAL(&skex_msg->key), GQUIC_STR_SIZE(&pubkey) + 4);
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&pubkey, GQUIC_STR_SIZE(&pubkey)))) {
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&pubkey), GQUIC_STR_VAL(&ser_ecdh_params) + 4, GQUIC_STR_SIZE(&pubkey));
    sig.size = GQUIC_STR_SIZE(&skex_msg->key) - GQUIC_STR_SIZE(&ser_ecdh_params);
    if (GQUIC_STR_SIZE(&sig) < 2) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ECDH_SIG_INVALID);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&sig, GQUIC_STR_SIZE(&sig)))) {
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&skex_msg->key) + GQUIC_STR_SIZE(&ser_ecdh_params), GQUIC_STR_SIZE(&sig));
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_ecdhe_params_generate(&ecdhe_self->params, curve_id))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_self->params, &ecdhe_self->pre_master_sec, &pubkey))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_self->params, &self_pubkey))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(&ecdhe_self->ckex_msg->cipher, 1 + GQUIC_STR_SIZE(&self_pubkey)))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(GQUIC_STR_VAL(&ecdhe_self->ckex_msg->cipher), &self_pubkey.size, 1))) {
        goto failure;
    }
    memcpy(GQUIC_STR_VAL(&ecdhe_self->ckex_msg->cipher) + 1, GQUIC_STR_VAL(&self_pubkey), GQUIC_STR_SIZE(&self_pubkey));

    if (ecdhe_self->ver >= GQUIC_TLS_VERSION_12) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(&sigalg, GQUIC_STR_VAL(&sig), 2))) {
            goto failure;
        }
        memmove(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&sig) + 2, GQUIC_STR_SIZE(&sig) - 2);
        sig.size -= 2;
        if (GQUIC_STR_SIZE(&sig) < 2) {
            GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_ECDH_SIG_INVALID);
            goto failure;
        }
    }
    u_int16_t *c_sup_sigalg = NULL;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &c_sup_sigalg, sizeof(u_int16_t)))) {
        goto failure;
    }
    gquic_list_insert_after(&c_sup_sigalgs, c_sup_sigalg);
    *(u_int16_t *) GQUIC_LIST_FIRST(&c_sup_sigalgs) = sigalg;
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_tls_selected_sigalg(&sigalg, &sig_type,
                                                     &hash,
                                                     cert_pubkey, &c_sup_sigalgs, &c_hello->supported_sign_algos, ecdhe_self->ver))) {
        goto failure;
    }
    if (ecdhe_self->is_rsa != (sig_type == GQUIC_SIG_PKCS1V15 || sig_type == GQUIC_SIG_RSAPSS)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TLS_RSA_SIG_INVALID);
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_big_endian_transfer(&sig_len, GQUIC_STR_VAL(&sig), 2))) {
        goto failure;
    }
    if (sig_len + 2 != GQUIC_STR_SIZE(&sig)) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        goto failure;
    }
    memmove(GQUIC_STR_VAL(&sig), GQUIC_STR_VAL(&sig) + 2, GQUIC_STR_SIZE(&sig) - 2);
    sig.size -= 2;
    const gquic_str_t **tmp = NULL;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &c_hello->random;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &s_hello->random;
    gquic_list_alloc((void **) &tmp, sizeof(const gquic_str_t *));
    gquic_list_insert_before(&slices, tmp);
    *tmp = &ser_ecdh_params;
    if (GQUIC_ASSERT_CAUSE(exception, hash_for_ser_key_exchange(&sign, sig_type, hash, ecdhe_self->ver, &slices))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_tls_verify_handshake_sign(hash, cert_pubkey, &sign, &sig))) {
        goto failure;
    }
    
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sig);
    gquic_str_reset(&self_pubkey);
    while (!gquic_list_head_empty(&c_sup_sigalgs)) gquic_list_release(GQUIC_LIST_FIRST(&c_sup_sigalgs));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(GQUIC_LIST_FIRST(&slices));
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&ser_ecdh_params);
    gquic_str_reset(&pubkey);
    gquic_str_reset(&sig);
    gquic_str_reset(&self_pubkey);
    gquic_str_reset(&ecdhe_self->pre_master_sec);
    while (!gquic_list_head_empty(&c_sup_sigalgs)) gquic_list_release(GQUIC_LIST_FIRST(&c_sup_sigalgs));
    while (!gquic_list_head_empty(&slices)) gquic_list_release(GQUIC_LIST_FIRST(&slices));
    gquic_tls_ecdhe_params_dtor(&ecdhe_self->params);
    GQUIC_PROCESS_DONE(exception);
}

static int ecdhe_ka_generate_cli_key_exchange(gquic_str_t *const pre_master_sec,
                                              gquic_tls_client_key_exchange_msg_t *const ckex_msg,
                                              void *const self,
                                              const gquic_tls_config_t *const cfg,
                                              const gquic_tls_client_hello_msg_t *const c_hello,
                                              X509 *const cert) {
    (void) cfg;
    (void) c_hello;
    (void) cert;
    gquic_tls_ecdhe_key_agreement_t *ecdhe_self = self;
    if (pre_master_sec == NULL || ckex_msg == NULL || self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(pre_master_sec);
    GQUIC_TLS_MSG_INIT(ckex_msg);
    gquic_str_copy(pre_master_sec, &ecdhe_self->pre_master_sec);
    gquic_str_copy(&ckex_msg->cipher, &ecdhe_self->ckex_msg->cipher);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int hash_for_ser_key_exchange(gquic_str_t *const ret,
                                     const u_int8_t sig_type,
                                     const EVP_MD *const hash,
                                     const u_int16_t ver,
                                     const gquic_list_t *const slices) {
    gquic_str_init(ret);
    size_t slices_size = 0;
    gquic_str_t **slice;
    gquic_str_t mid;
    int exception = GQUIC_SUCCESS;
    if (ret == NULL || slices == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&mid);
    gquic_str_init(ret);
    GQUIC_LIST_FOREACH(slice, slices){ slices_size += GQUIC_STR_SIZE(*slice); }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&mid, slices_size));
    slices_size = 0;
    GQUIC_LIST_FOREACH(slice, slices) {
        memcpy(GQUIC_STR_VAL(&mid) + slices_size, GQUIC_STR_VAL(*slice), GQUIC_STR_SIZE(*slice));
        slices_size += GQUIC_STR_SIZE(*slice);
    }
    if (sig_type == GQUIC_SIG_ED25519) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_copy(ret, &mid))) {
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(exception);
        }
        gquic_str_reset(&mid);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (ver >= GQUIC_TLS_VERSION_12) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(ctx, hash, NULL) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_FAILED);
        }
        if (EVP_DigestUpdate(ctx, GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid)) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_FAILED);
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(ret, EVP_MD_size(hash)))) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(exception);
        }
        if (EVP_DigestFinal_ex(ctx, GQUIC_STR_VAL(ret), NULL) <= 0) {
            EVP_MD_CTX_free(ctx);
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DIGEST_FAILED);
        }
        gquic_str_reset(&mid);
        EVP_MD_CTX_free(ctx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (sig_type == GQUIC_SIG_ECDSA) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(ret, SHA_DIGEST_LENGTH))) {
            gquic_str_reset(&mid);
            GQUIC_PROCESS_DONE(exception);
        }
        SHA1(GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid), GQUIC_STR_VAL(ret));
        gquic_str_reset(&mid);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_str_alloc(ret, MD5_DIGEST_LENGTH))) {
        gquic_str_reset(&mid);
        GQUIC_PROCESS_DONE(exception);
    }
    MD5(GQUIC_STR_VAL(&mid), GQUIC_STR_SIZE(&mid), GQUIC_STR_VAL(ret));
    gquic_str_reset(&mid);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

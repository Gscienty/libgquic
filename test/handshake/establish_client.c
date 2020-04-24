#include "handshake/establish.h"
#include "tls/key_schedule.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/cert_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/auth.h"
#include "tls/finished_msg.h"
#include "tls/meta.h"
#include "net/addr.h"
#include "unit_test.h"
#include "util/malloc.h"
#include "global_schedule.h"
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

gquic_handshake_establish_t est;
gquic_coroutine_t *co = NULL;

static gquic_str_t sess_id = { 0, NULL };
static gquic_str_t client_pubkey = { 0, NULL };
static gquic_str_t sser_sec = { 0, NULL };

static gquic_tls_mac_t transport;

static int client_hello_process(const gquic_str_t *const chello_buf) {
    printf("client say: CHELLO \n");
    gquic_str_test_echo(chello_buf);

    gquic_tls_client_hello_msg_t *chello ;
    gquic_tls_client_hello_msg_alloc(&chello);
    GQUIC_TLS_MSG_INIT(chello);
    gquic_reader_str_t reader = *chello_buf;
    GQUIC_TLS_MSG_DESERIALIZE(chello, &reader);

    gquic_str_copy(&sess_id, &chello->sess_id);
    gquic_tls_key_share_t *key_share = gquic_list_next(GQUIC_LIST_PAYLOAD(&chello->key_shares));
    gquic_str_copy(&client_pubkey, &key_share->data);
    gquic_tls_mac_md_update(&transport, chello_buf);
    return 0;
}

static int server_hello_handshake_msg(gquic_str_t *const msg) {
    gquic_tls_server_hello_msg_t *hello;
    gquic_tls_server_hello_msg_alloc(&hello);
    GQUIC_TLS_MSG_INIT(hello);

    hello->vers = GQUIC_TLS_VERSION_13;
    hello->supported_version = GQUIC_TLS_VERSION_13;
    gquic_str_alloc(&hello->random, 32);
    RAND_bytes(GQUIC_STR_VAL(&hello->random), 32);
    gquic_str_copy(&hello->sess_id, &sess_id);
    hello->cipher_suite = GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    /*gquic_str_t cookie = { 6, "cookie" };*/
    /*gquic_str_copy(&hello->cookie, &cookie);*/
    hello->ser_share.group = GQUIC_TLS_CURVE_X25519;
    gquic_tls_ecdhe_params_t ecdhe;
    gquic_tls_ecdhe_params_init(&ecdhe);
    gquic_tls_ecdhe_params_generate(&ecdhe, GQUIC_TLS_CURVE_X25519);
    GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe, &hello->ser_share.data);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(hello));
    gquic_reader_str_t writer = *msg;
    GQUIC_TLS_MSG_SERIALIZE(hello, &writer);

    printf("server say: SHELLO\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);

    gquic_str_t shared_key = { 0, NULL };
    GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe, &shared_key, &client_pubkey);
    const gquic_tls_cipher_suite_t *cipher_suite;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    gquic_str_t early_sec = { 0, NULL };
    gquic_tls_cipher_suite_extract(&early_sec, cipher_suite, NULL, NULL);
    gquic_str_t early_sec_derived_sec = { 0, NULL };
    static const gquic_str_t derived_label = { 7, "derived" };
    gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, cipher_suite, NULL, &early_sec, &derived_label);
    gquic_str_t handshake_sec = { 0, NULL };
    gquic_tls_cipher_suite_extract(&handshake_sec, cipher_suite, &shared_key, &early_sec_derived_sec);
    gquic_str_t ser_sec = { 0, NULL };
    static const gquic_str_t ser_handshake_traffic_label = { 12, "s hs traffic" };
    gquic_tls_cipher_suite_derive_secret(&ser_sec, cipher_suite, &transport, &handshake_sec, &ser_handshake_traffic_label);
    printf("server ser_sec\n");
    gquic_str_test_echo(&ser_sec);
    gquic_str_copy(&sser_sec, &ser_sec);
    return 0;
}

static int encrypted_exts_handshake_msg(gquic_str_t *const msg) {
    gquic_tls_encrypt_ext_msg_t *ext;
    gquic_tls_encrypt_ext_msg_alloc(&ext);
    GQUIC_TLS_MSG_INIT(ext);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(ext));
    gquic_writer_str_t writer = *msg;
    GQUIC_TLS_MSG_SERIALIZE(ext, &writer);
    
    printf("server say EXTS:\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);
    return 0;
}

static int cert_msg(gquic_str_t *const msg) {
    gquic_tls_cert_msg_t *cert;
    gquic_tls_cert_msg_alloc(&cert);
    GQUIC_TLS_MSG_INIT(cert);

    X509 **x509_storage;
    gquic_list_alloc((void **) &x509_storage, sizeof(X509 *));
    X509 *x509 = NULL;
    FILE *x509_f = fopen("test_certs/ed25519_req.pem", "r");
    PEM_read_X509(x509_f, &x509, NULL, NULL);
    fclose(x509_f);
    *x509_storage = x509;

    gquic_list_insert_before(&cert->cert.certs, x509_storage);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(cert));
    gquic_writer_str_t writer = *msg;
    GQUIC_TLS_MSG_SERIALIZE(cert, &writer);
    printf("server say: CERT\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);
    return 0;
}

static int verify_msg(gquic_str_t *const msg) {
    static const gquic_str_t ser_sign_cnt = { 38, "GQUIC-TLSv1.3, server SignatureContent" };
    gquic_str_t sum = { 0, NULL };
    gquic_str_t verify_msg = { 0, NULL };
    gquic_tls_mac_md_sum(&sum, &transport);

    gquic_tls_cert_verify_msg_t *verify;
    gquic_tls_cert_verify_msg_alloc(&verify);
    GQUIC_TLS_MSG_INIT(verify);

    verify->sign_algo = GQUIC_SIGALG_ED25519;
    verify->has_sign_algo = 1;
    gquic_tls_signed_msg(&verify_msg, NULL, &ser_sign_cnt, &transport);

    FILE *pkey_f = fopen("test_certs/ed25519_pkey.pem", "r");
    EVP_PKEY *pkey = PEM_read_PrivateKey(pkey_f, NULL, NULL, NULL);
    fclose(pkey_f);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);

    EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    
    size_t sign_len = 0;
    EVP_DigestSign(ctx, NULL, &sign_len, GQUIC_STR_VAL(&verify_msg), GQUIC_STR_SIZE(&verify_msg));
    gquic_str_alloc(&verify->sign, sign_len);
    EVP_DigestSign(ctx, GQUIC_STR_VAL(&verify->sign), &sign_len, GQUIC_STR_VAL(&verify_msg), GQUIC_STR_SIZE(&verify_msg));

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(verify));
    gquic_writer_str_t writer = *msg;
    GQUIC_TLS_MSG_SERIALIZE(verify, &writer);
    printf("server say VERIFY\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);
    return 0;
}

static int finish_msg(gquic_str_t *const msg) {
    gquic_tls_finished_msg_t *finished;
    gquic_tls_finished_msg_alloc(&finished);
    GQUIC_TLS_MSG_INIT(finished);

    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    gquic_tls_cipher_suite_finished_hash(&finished->verify, cipher_suite, &sser_sec, &transport);

    printf("server verify:\n");
    gquic_str_test_echo(&finished->verify);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(finished));
    gquic_writer_str_t writer = *msg;
    GQUIC_TLS_MSG_SERIALIZE(finished, &writer);
    printf("server say: FIN\n");
    gquic_str_test_echo(msg);
    return 0;
}

static int gquic_handshake_mock_server_run_co(gquic_coroutine_t *const co, void *const est_) {
    (void) est_;
    gquic_str_t msg = { 0, NULL };
    gquic_str_t *tmp = NULL;

    server_hello_handshake_msg(&msg);
    GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
    gquic_str_copy(tmp, &msg);
    gquic_handshake_establish_handle_msg(co, &est, tmp, GQUIC_ENC_LV_INITIAL);

    printf("server inner\n");

    encrypted_exts_handshake_msg(&msg);
    GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
    gquic_str_copy(tmp, &msg);
    gquic_handshake_establish_handle_msg(co, &est, tmp, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    cert_msg(&msg);
    GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
    gquic_str_copy(tmp, &msg);
    gquic_handshake_establish_handle_msg(co, &est, tmp, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    verify_msg(&msg);
    GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
    gquic_str_copy(tmp, &msg);
    gquic_handshake_establish_handle_msg(co, &est, tmp, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    finish_msg(&msg);
    GQUIC_MALLOC_STRUCT(&tmp, gquic_str_t);
    gquic_str_copy(tmp, &msg);
    gquic_handshake_establish_handle_msg(co, &est, tmp, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static void *server_thread(void *const _) {
    (void) _;
    gquic_coroutine_t *co = NULL;
    gquic_coroutine_alloc(&co);
    gquic_coroutine_ctor(co, 4096 * 4096, gquic_handshake_mock_server_run_co, &est);
    gquic_coroutine_schedule_join(gquic_get_global_schedule(), co);
    return NULL;
}

static int init_write(void *const self, gquic_writer_str_t *const writer) {
    switch (*(int *) self) {
    case 0:
        client_hello_process(writer);
        server_thread(NULL);
        break;
    }
    (*(int *) self)++;
    return 0;
}

static int handshake_write(void *const self, gquic_writer_str_t *const writer) {
    (void) self;
    printf("cli say: FIN\n");
    gquic_str_test_echo(writer);
    return 0;
}

static int one_rtt_write(void *const self, gquic_writer_str_t *const writer) {
    (void) self;
    printf("cli say: FIN\n");
    gquic_str_test_echo(writer);
    return 0;
}

int gquic_handshake_establish_run_co(gquic_coroutine_t *const co, void *const est_) {
    gquic_handshake_establish_run(co, est_);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(establish_client) {
    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    cipher_suite->mac(&transport, 0, NULL);

    gquic_tls_config_t cfg;
    gquic_str_t conn_id = { 0, NULL };
    gquic_transport_parameters_t params;
    gquic_rtt_t rtt;
    gquic_net_addr_t addr;

    gquic_transport_parameters_init(&params);
    gquic_rtt_init(&rtt);

    gquic_net_str_to_addr_v4(&addr, "127.0.0.1");
    gquic_tls_config_init(&cfg);
    gquic_handshake_establish_init(&est);
    cfg.insecure_skiy_verify = 1;

    int init = 0;
    int handshake = 0;

    GQUIC_ASSERT_FAST_RETURN(gquic_handshake_establish_ctor(&est,
                                                            &init, init_write,
                                                            &handshake, handshake_write,
                                                            &one_rtt_write, one_rtt_write,
                                                            NULL, NULL,
                                                            &cfg, &conn_id, &params, &rtt, &addr, 1));

    gquic_coroutine_alloc(&co);
    gquic_coroutine_ctor(co, 4096 * 4096, gquic_handshake_establish_run_co, &est);
    gquic_coroutine_schedule_join(gquic_get_global_schedule(), co);
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());
    gquic_coroutine_schedule_resume(gquic_get_global_schedule());

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

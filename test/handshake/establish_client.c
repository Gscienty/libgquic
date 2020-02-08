#include "handshake/establish.h"
#include "tls/key_schedule.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/cert_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/auth.h"
#include "tls/finished_msg.h"
#include "net/addr.h"
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

gquic_handshake_establish_t est;

static gquic_str_t sess_id = { 0, NULL };
static gquic_str_t client_pubkey = { 0, NULL };
static gquic_str_t sser_sec = { 0, NULL };

static gquic_tls_mac_t transport;

static int client_hello_process(const gquic_str_t *const chello_buf) {
    printf("client say: CHELLO \n");
    gquic_str_test_echo(chello_buf);

    gquic_tls_client_hello_msg_t chello;
    gquic_tls_client_hello_msg_init(&chello);
    gquic_tls_client_hello_msg_deserialize(&chello, GQUIC_STR_VAL(chello_buf), GQUIC_STR_SIZE(chello_buf));

    gquic_str_copy(&sess_id, &chello.sess_id);
    gquic_tls_key_share_t *key_share = gquic_list_next(GQUIC_LIST_PAYLOAD(&chello.key_shares));
    gquic_str_copy(&client_pubkey, &key_share->data);
    gquic_tls_mac_md_update(&transport, chello_buf);
    return 0;
}

static int server_hello_handshake_msg(gquic_str_t *const msg) {
    gquic_tls_server_hello_msg_t hello;
    gquic_tls_server_hello_msg_init(&hello);

    hello.vers = GQUIC_TLS_VERSION_13;
    hello.supported_version = GQUIC_TLS_VERSION_13;
    gquic_str_alloc(&hello.random, 32);
    RAND_bytes(GQUIC_STR_VAL(&hello.random), 32);
    gquic_str_copy(&hello.sess_id, &sess_id);
    hello.cipher_suite = GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    gquic_str_t cookie = { 6, "cookie" };
    gquic_str_copy(&hello.cookie, &cookie);
    hello.ser_share.group = GQUIC_TLS_CURVE_X25519;
    gquic_tls_ecdhe_params_t ecdhe;
    gquic_tls_ecdhe_params_init(&ecdhe);
    gquic_tls_ecdhe_params_generate(&ecdhe, GQUIC_TLS_CURVE_X25519);
    GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe, &hello.ser_share.data);

    gquic_str_alloc(msg, gquic_tls_server_hello_msg_size(&hello));
    gquic_tls_server_hello_msg_serialize(&hello, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));

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
    gquic_tls_encrypt_ext_msg_t ext;
    gquic_tls_encrypt_ext_msg_init(&ext);

    gquic_str_alloc(msg, gquic_tls_encrypt_ext_msg_size(&ext));
    gquic_tls_encrypt_ext_msg_serialize(&ext, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
    
    printf("server say EXTS:\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);
    return 0;
}

static int cert_msg(gquic_str_t *const msg) {
    gquic_tls_cert_13_msg_t cert;
    gquic_tls_cert_13_msg_init(&cert);

    gquic_str_t *x509_b = gquic_list_alloc(sizeof(gquic_str_t));
    X509 *x509 = NULL;
    FILE *x509_f = fopen("test_certs/ed25519_req.pem", "r");
    PEM_read_X509(x509_f, &x509, NULL, NULL);
    gquic_str_alloc(x509_b, i2d_X509(x509, NULL));
    unsigned char *ug = GQUIC_STR_VAL(x509_b);
    i2d_X509(x509, &ug);
    X509_free(x509);
    fclose(x509_f);

    gquic_list_insert_before(&cert.cert.certs, x509_b);

    gquic_str_alloc(msg, gquic_tls_cert_13_msg_size(&cert));
    gquic_tls_cert_13_msg_serialize(&cert, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
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

    gquic_tls_cert_verify_msg_t verify;
    gquic_tls_cert_verify_msg_init(&verify);

    verify.sign_algo = GQUIC_SIGALG_ED25519;
    verify.has_sign_algo = 1;
    gquic_tls_signed_msg(&verify_msg, NULL, &ser_sign_cnt, &transport);

    FILE *pkey_f = fopen("test_certs/ed25519_pkey.pem", "r");
    EVP_PKEY *pkey = PEM_read_PrivateKey(pkey_f, NULL, NULL, NULL);
    fclose(pkey_f);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);

    EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    
    size_t sign_len = 0;
    EVP_DigestSign(ctx, NULL, &sign_len, GQUIC_STR_VAL(&verify_msg), GQUIC_STR_SIZE(&verify_msg));
    gquic_str_alloc(&verify.sign, sign_len);
    EVP_DigestSign(ctx, GQUIC_STR_VAL(&verify.sign), &sign_len, GQUIC_STR_VAL(&verify_msg), GQUIC_STR_SIZE(&verify_msg));

    gquic_str_alloc(msg, gquic_tls_cert_verify_msg_size(&verify));
    gquic_tls_cert_verify_msg_serialize(&verify, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
    printf("server say VERIFY\n");
    gquic_str_test_echo(msg);
    gquic_tls_mac_md_update(&transport, msg);
    return 0;
}

static int finish_msg(gquic_str_t *const msg) {
    gquic_tls_finished_msg_t finished;
    gquic_tls_finished_msg_init(&finished);

    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    gquic_tls_cipher_suite_finished_hash(&finished.verify, cipher_suite, &sser_sec, &transport);

    printf("server verify:\n");
    gquic_str_test_echo(&finished.verify);

    gquic_str_alloc(msg, gquic_tls_finished_msg_size(&finished));
    gquic_tls_finished_msg_serialize(&finished, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
    printf("server say: FIN\n");
    gquic_str_test_echo(msg);
    return 0;
}

static void *server_thread(void *const _) {
    (void) _;
    gquic_str_t msg = { 0, NULL };

    server_hello_handshake_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_INITIAL);

    printf("server inner\n");

    encrypted_exts_handshake_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    cert_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    verify_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    finish_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_HANDSHAKE);

    printf("server inner\n");

    return NULL;
}

static int init_write(size_t *const size, void *const self, const gquic_str_t *const data) {
    (void) size;
    pthread_attr_t attr;
    pthread_t thread;
    pthread_attr_init(&attr);
    switch (*(int *) self) {
    case 0:
        client_hello_process(data);
        pthread_create(&thread, &attr, server_thread, NULL);
        break;
    }
    (*(int *) self)++;
    return 0;
}

static int handshake_write(size_t *const size, void *const self, const gquic_str_t *const data) {
    (void) size;
    (void) self;
    printf("cli say: FIN\n");
    gquic_str_test_echo(data);
    return 0;
}

int main() {
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

    gquic_handshake_establish_assign(&est, &cfg, &conn_id, &params, &rtt, &addr, 1);
    int init_output_step = 0;
    est.init_output.self = &init_output_step;
    est.init_output.write = init_write;
    int handshake_output_step = 0;
    est.handshake_output.self = &handshake_output_step;
    est.handshake_output.write = handshake_write;


    int ret = gquic_handshake_establish_run(&est);
    printf("here: %d\n", ret);
    return 0;
}

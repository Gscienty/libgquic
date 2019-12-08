#include "tls/handshake_client.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/cert_13_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/auth.h"
#include "tls/finished_msg.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static gquic_str_t sess_id = { 0, NULL };
static gquic_str_t client_pubkey = { 0, NULL };
static gquic_str_t sser_sec = { 0, NULL };

static gquic_tls_mac_t transport;

static int write_client_hello_record(const gquic_str_t *const chello_buf) {
    printf("REC CHELLO: \n");
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

static int write_record(size_t *const size, void *const self, const gquic_str_t *const buf) {
    (void) size;
    (void) self;
    write_client_hello_record(buf);
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

    printf("SEN SHELLO:\n");
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
    printf("SERVER ser_sec\n");
    gquic_str_test_echo(&ser_sec);
    gquic_str_copy(&sser_sec, &ser_sec);
    return 0;
}

static int encrypted_exts_handshake_msg(gquic_str_t *const msg) {
    gquic_tls_encrypt_ext_msg_t ext;
    gquic_tls_encrypt_ext_msg_init(&ext);

    gquic_str_alloc(msg, gquic_tls_encrypt_ext_msg_size(&ext));
    gquic_tls_encrypt_ext_msg_serialize(&ext, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
    
    printf("SEN ENC EXTS:\n");
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
    printf("SEN CERT:\n");
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
    printf("SEN VERI:\n");
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

    printf("verify:\n");
    gquic_str_test_echo(&finished.verify);

    gquic_str_alloc(msg, gquic_tls_finished_msg_size(&finished));
    gquic_tls_finished_msg_serialize(&finished, GQUIC_STR_VAL(msg), GQUIC_STR_SIZE(msg));
    printf("SEN FIN:\n");
    gquic_str_test_echo(msg);
    return 0;
}

static int read_handshake_msg(gquic_str_t *const msg, void *self) {
    switch (*(int *) self) {
    case 0:
        server_hello_handshake_msg(msg);
        break;
    case 1:
        encrypted_exts_handshake_msg(msg);
        break;
    case 2:
        cert_msg(msg);
        break;
    case 3:
        verify_msg(msg);
        break;
    case 4:
        finish_msg(msg);
        break;
    }

    (*(int *) self)++;
    return 0;
}

int main() {
    int ret;
    gquic_net_addr_t addr;
    gquic_net_str_to_addr_v4(&addr, "127.0.0.1");
    gquic_tls_config_t cfg;
    gquic_tls_config_init(&cfg);
    gquic_tls_conn_t conn;
    gquic_tls_conn_init(&conn);
    conn.addr = &addr;
    conn.cfg = &cfg;
    int step = 0;

    cfg.insecure_skiy_verify = 1;
    cfg.alt_record.write_record = write_record;
    cfg.alt_record.read_handshake_msg = read_handshake_msg;
    cfg.alt_record.self = &step;

    conn.ver = GQUIC_TLS_VERSION_13;

    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    cipher_suite->mac(&transport, 0, NULL);

    ret = gquic_tls_client_handshake(&conn);
    printf("%d\n", ret);

    return 0;
}

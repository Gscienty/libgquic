#include "tls/handshake_server.h"
#include "handshake/establish.h"
#include "tls/encrypt_ext_msg.h"
#include "tls/cert_msg.h"
#include "tls/cert_verify_msg.h"
#include "tls/auth.h"
#include "tls/finished_msg.h"
#include "tls/key_schedule.h"
#include "tls/meta.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <stdlib.h>

gquic_handshake_establish_t est;
gquic_tls_config_t cfg;
static gquic_tls_mac_t transport;
gquic_tls_ecdhe_params_t ecdhe_params;
gquic_str_t server_pubkey = { 0, NULL };
gquic_str_t shared_key = { 0, NULL };
gquic_str_t scli_sec = { 0, NULL };

static int init_write(void *const self, gquic_writer_str_t *const buf) {
    gquic_tls_mac_md_update(&transport, buf);
    switch (*(int *) self) {
    case 0: {
                printf("server say SHELLO\n");
                gquic_str_test_echo(buf);

                gquic_tls_server_hello_msg_t *hello = gquic_tls_server_hello_msg_alloc();
                GQUIC_TLS_MSG_INIT(hello);
                gquic_reader_str_t reader = *buf;
                GQUIC_TLS_MSG_DESERIALIZE(hello, &reader);

                GQUIC_TLS_ECDHE_PARAMS_SHARED_KEY(&ecdhe_params, &shared_key, &hello->ser_share.data);
                const gquic_tls_cipher_suite_t *cipher_suite;
                gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
                gquic_str_t early_sec = { 0, NULL };
                gquic_tls_cipher_suite_extract(&early_sec, cipher_suite, NULL, NULL);
                gquic_str_t early_sec_derived_sec = { 0, NULL };
                static const gquic_str_t derived_label = { 7, "derived" };
                gquic_tls_cipher_suite_derive_secret(&early_sec_derived_sec, cipher_suite, NULL, &early_sec, &derived_label);
                gquic_str_t handshake_sec = { 0, NULL };
                gquic_tls_cipher_suite_extract(&handshake_sec, cipher_suite, &shared_key, &early_sec_derived_sec);
                static const gquic_str_t cli_handshake_traffic_label = { 12, "c hs traffic" };
                gquic_tls_cipher_suite_derive_secret(&scli_sec, cipher_suite, &transport, &handshake_sec, &cli_handshake_traffic_label);
            }
            break;
    }

    (*(int *) self)++;
    return 0;
}

static int read_cli_finished(gquic_str_t *const msg) {
    gquic_tls_finished_msg_t *finished = gquic_tls_finished_msg_alloc();
    GQUIC_TLS_MSG_INIT(finished);

    const gquic_tls_cipher_suite_t *cipher_suite = NULL;
    gquic_tls_get_cipher_suite(&cipher_suite, GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    gquic_tls_cipher_suite_finished_hash(&finished->verify, cipher_suite, &scli_sec, &transport);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(finished));
    gquic_reader_str_t reader = *msg;
    GQUIC_TLS_MSG_SERIALIZE(finished, &reader);

    printf("client say: FIN\n");
    gquic_str_test_echo(msg);
    return 0;
}

static int handshake_write(void *const self, gquic_writer_str_t *const data) {

    gquic_tls_mac_md_update(&transport, data);
    switch (*(int *) self) {
    case 0: 
        printf("server say: EXT\n");
        break;
    case 1:
        printf("server say: CERT\n");
        break;
    case 2:
        printf("server say: VERIFY\n");
        break;
    case 3:
        printf("server say: FIN\n");
        break;
    }

    gquic_str_test_echo(data);

    (*(int *) self)++;
    return 0;
}

static int get_cert(PKCS12 **const p12_storage, const gquic_tls_client_hello_msg_t *const hello) {
    (void) hello;
    FILE *f = fopen("test_certs/ed25519_p12.pem", "r");
    PKCS12 *p12 = d2i_PKCS12_fp(f, NULL);
    fclose(f);
    *p12_storage = p12;
    return 0;
}

static int client_hello_handshake_msg(gquic_str_t *const msg) {
    static u_int16_t __cipher_suites[] = {
        GQUIC_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        GQUIC_TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        GQUIC_TLS_CIPHER_SUITE_AES_256_GCM_SHA384
    };
    static u_int16_t __supported_sign_algos[] = {
        GQUIC_SIGALG_ED25519,
        GQUIC_SIGALG_PSS_SHA256,
        GQUIC_SIGALG_ECDSA_P256_SHA256,
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

    gquic_tls_client_hello_msg_t *hello = gquic_tls_client_hello_msg_alloc();
    GQUIC_TLS_MSG_INIT(hello);
    hello->vers = GQUIC_TLS_VERSION_13;
    gquic_str_alloc(&hello->compression_methods, 1);
    *(u_int8_t *) GQUIC_STR_VAL(&hello->compression_methods) = 0;
    gquic_str_alloc(&hello->random, 32);
    gquic_str_alloc(&hello->sess_id, 32);
    hello->ocsp_stapling = 1;
    hello->scts = 1;
    gquic_tls_config_curve_preferences(&hello->supported_curves);
    gquic_str_alloc(&hello->supported_points, 1);
    *(u_int8_t *) GQUIC_STR_VAL(&hello->supported_points) = 0;
    hello->secure_regegotiation_supported = 1;
    gquic_tls_config_supported_versions(&hello->supported_versions, &cfg, 1);
    size_t count = sizeof(__cipher_suites) / sizeof(u_int16_t);
    size_t i;
    for (i = 0; i < count; i++) {
        u_int16_t *cipher_suite = gquic_list_alloc(sizeof(u_int16_t));
        *cipher_suite = __cipher_suites[i];
        gquic_list_insert_before(&hello->cipher_suites, cipher_suite);
    }
    RAND_bytes(GQUIC_STR_VAL(&hello->random), GQUIC_STR_SIZE(&hello->random));
    RAND_bytes(GQUIC_STR_VAL(&hello->sess_id), GQUIC_STR_SIZE(&hello->sess_id));
    count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
    for (i = 0; i < count; i++) {
        u_int16_t *sigalg = gquic_list_alloc(sizeof(u_int16_t));
        *sigalg = __supported_sign_algos[i];
        gquic_list_insert_before(&hello->supported_sign_algos, sigalg);
    }

    gquic_tls_ecdhe_params_init(&ecdhe_params);
    gquic_tls_ecdhe_params_generate(&ecdhe_params, GQUIC_TLS_CURVE_X25519);
    gquic_tls_key_share_t *key_share = gquic_list_alloc(sizeof(gquic_tls_key_share_t));
    key_share->group = GQUIC_TLS_CURVE_X25519;
    gquic_str_init(&key_share->data);
    GQUIC_TLS_ECDHE_PARAMS_PUBLIC_KEY(&ecdhe_params, &key_share->data);
    gquic_list_insert_before(&hello->key_shares, key_share);

    gquic_str_alloc(msg, GQUIC_TLS_MSG_SIZE(hello));
    gquic_reader_str_t reader = *msg;
    GQUIC_TLS_MSG_SERIALIZE(hello, &reader);
    gquic_tls_mac_md_update(&transport, msg);

    printf("client say: CHELLO\n");
    gquic_str_test_echo(msg);
    return 0;
}

static void *server_thread(void *const _) {
    (void) _;
    sleep(1);

    gquic_str_t msg = { 0, NULL };

    client_hello_handshake_msg(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_INITIAL);

    sleep(1);
    read_cli_finished(&msg);
    gquic_handshake_establish_handle_msg(&est, &msg, GQUIC_ENC_LV_HANDSHAKE);

    return NULL;
}

static int one_rtt_write(void *const self, gquic_writer_str_t *const writer) {
    (void) self;
    printf("ser say: FIN\n");
    gquic_str_test_echo(writer);
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
    cfg.get_ser_cert = get_cert;

    int init = 0;
    int handshake = 0;
    gquic_handshake_establish_ctor(&est,
                                   &init, init_write,
                                   &handshake, handshake_write,
                                   main, one_rtt_write,
                                   NULL, NULL,
                                   &cfg, &conn_id, &params, &rtt, &addr, 0);

    pthread_attr_t attr;
    pthread_t thread;
    pthread_attr_init(&attr);
    pthread_create(&thread, &attr, server_thread, NULL);

    int ret = gquic_handshake_establish_run(&est);
    printf("here: %d\n", ret);
    return 0;
}

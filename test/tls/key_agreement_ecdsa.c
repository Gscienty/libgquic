#include "tls/key_agreement.h"
#include "tls/config.h"
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

static u_int16_t __supported_sign_algos[] = {
    GQUIC_SIGALG_ED25519,
    GQUIC_SIGALG_ECDSA_P256_SHA256,
    GQUIC_SIGALG_PSS_SHA256,
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

int main() {
    gquic_str_t pms;
    gquic_str_t p12_d;
    gquic_tls_key_agreement_t s_ka;
    gquic_tls_key_agreement_t c_ka;
    gquic_tls_server_key_exchange_msg_t sk;
    gquic_tls_client_hello_msg_t chello;
    gquic_tls_server_hello_msg_t shello;
    gquic_tls_config_t cfg;
    unsigned char *buf;

    gquic_tls_key_agreement_ecdhe_init(&c_ka);
    gquic_tls_key_agreement_ecdhe_init(&s_ka);
    gquic_tls_client_hello_msg_init(&chello);
    gquic_tls_server_hello_msg_init(&shello);
    gquic_tls_server_key_exchange_msg_init(&sk);
    gquic_tls_config_init(&cfg);
    gquic_str_init(&pms);
    gquic_str_init(&p12_d);

    FILE *p12file = fopen("test_certs/ec_p12.pem", "r");
    PKCS12 *p12 = d2i_PKCS12_fp(p12file, NULL);
    gquic_str_alloc(&p12_d, i2d_PKCS12(p12, NULL));
    buf = GQUIC_STR_VAL(&p12_d);
    i2d_PKCS12(p12, (unsigned char **) &buf);

    gquic_tls_config_curve_preferences(&chello.supported_curves);
    gquic_tls_key_agreement_ecdhe_set_version(&s_ka, GQUIC_TLS_VERSION_12);
    gquic_tls_key_agreement_ecdhe_set_version(&c_ka, GQUIC_TLS_VERSION_12);

    gquic_str_alloc(&chello.random, 32);
    gquic_str_alloc(&shello.random, 32);
    RAND_bytes(GQUIC_STR_VAL(&chello.random), GQUIC_STR_SIZE(&chello.random));
    RAND_bytes(GQUIC_STR_VAL(&shello.random), GQUIC_STR_SIZE(&shello.random));

    int ret = s_ka.generate_ser_key_exchange(&sk, s_ka.self, &cfg, &p12_d, &chello, &shello);
    printf("gener: %d\n", ret);
    size_t i;
    printf("sk:\n");
    for (i = 0; i < GQUIC_STR_SIZE(&sk.key); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&sk.key))[i]);
    printf("\n");

    // process ser key
    
    size_t count = sizeof(__supported_sign_algos) / sizeof(u_int16_t);
    for (i = 0; i < count; i++) {
        u_int16_t *sigalg = gquic_list_alloc(sizeof(u_int16_t));
        *sigalg = __supported_sign_algos[i];
        gquic_list_insert_before(&chello.supported_sign_algos, sigalg);
    }
    gquic_str_t cert;
    gquic_str_init(&cert);
    FILE *x509_f = fopen("test_certs/ec_x509.pem", "r");
    X509 *x509 = PEM_read_X509(x509_f, NULL, NULL, NULL);
    gquic_str_alloc(&cert, i2d_X509(x509, NULL));
    buf = GQUIC_STR_VAL(&cert);
    i2d_X509(x509, (unsigned char **) &buf);
    ret = c_ka.process_ser_key_exchange(c_ka.self, &cfg, &chello, &shello, &cert, &sk);
    printf("process sk: %d\n", ret);

    // generate cli key

    gquic_str_t c_pmk;
    gquic_tls_client_key_exchange_msg_t ck;
    
    gquic_str_init(&c_pmk);
    gquic_tls_client_key_exchange_msg_init(&ck);

    ret = c_ka.generate_cli_key_exchange(&c_pmk, &ck, c_ka.self, &cfg, &chello, &cert);
    printf("gener ck: %d\n", ret);
    printf("c_pmk:\n");
    for (i = 0; i < GQUIC_STR_SIZE(&c_pmk); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&c_pmk))[i]); printf("\n");
    printf("ck:\n");
    for (i = 0; i < GQUIC_STR_SIZE(&ck.cipher); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&ck.cipher))[i]); printf("\n");

    // process cli key

    gquic_str_t s_pmk;
    gquic_str_init(&s_pmk);

    ret = s_ka.process_cli_key_exchange(&s_pmk, s_ka.self, &cfg, &p12_d, &ck, GQUIC_TLS_VERSION_12);
    printf("process ck: %d\n", ret);
    printf("s_pmk:\n");
    for (i = 0; i < GQUIC_STR_SIZE(&s_pmk); i++) printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&s_pmk))[i]); printf("\n");

    return 0;
}

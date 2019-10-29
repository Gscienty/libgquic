#include "tls/key_agreement.h"
#include "tls/config.h"
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int main() {
    gquic_tls_key_agreement_t ka;
    gquic_str_t pms;
    gquic_str_t cert;
    gquic_tls_client_hello_msg_t chello;
    gquic_tls_client_key_exchange_msg_t ckmsg;
    gquic_tls_config_t cfg;
    X509 *x509;
    unsigned char *buf;

    gquic_str_init(&cert);
    gquic_tls_key_agreement_rsa_init(&ka);
    gquic_tls_client_hello_msg_init(&chello);
    gquic_str_init(&pms);
    gquic_tls_client_key_exchange_msg_init(&ckmsg);
    gquic_tls_config_init(&cfg);

    FILE *f = fopen("test_certs/rsa_x509.pem", "r");
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    gquic_str_alloc(&cert, i2d_X509(x509, NULL));
    buf = GQUIC_STR_VAL(&cert);
    i2d_X509(x509, (unsigned char **) &buf);


    chello.vers = GQUIC_TLS_VERSION_12;

    int ret = ka.generate_cli_key_exchange(&pms, &ckmsg, ka.self, &cfg, &chello, &cert);
    printf("ret: %d, PMS:\n", ret);
    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(&pms); i++) {
        printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&pms))[i]);
    }
    printf("\nCKMSG:\n");
    for (i = 0; i < GQUIC_STR_SIZE(&ckmsg.cipher); i++) {
        printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&ckmsg.cipher))[i]);
    }
    printf("\n");

    // ================================ ser =================

    FILE *p12file = fopen("test_certs/rsa_p12.pem", "r");
    PKCS12 *p12 = d2i_PKCS12_fp(p12file, NULL);
    gquic_str_t s_pms;
    gquic_str_t p12_d;
    gquic_str_init(&s_pms);
    gquic_str_init(&p12_d);
    gquic_str_alloc(&p12_d, i2d_PKCS12(p12, NULL));
    buf = GQUIC_STR_VAL(&p12_d);
    i2d_PKCS12(p12, (unsigned char **) &buf);

    ret = ka.process_cli_key_exchange(&s_pms, ka.self, &cfg, &p12_d, &ckmsg, GQUIC_TLS_VERSION_12);
    printf("ret:%d, PMS:\n", ret);
    for (i = 0; i < GQUIC_STR_SIZE(&s_pms); i++) {
        printf("%02x ", ((unsigned char *) GQUIC_STR_VAL(&s_pms))[i]);
    }
    printf("\n");

    return 0;
}

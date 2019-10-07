#include "tls/conn.h"
#include "tls/client_hello_msg.h"
#include "tls/handshake_client.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

static int _get(gquic_tls_client_sess_state_t **const state, const gquic_str_t *const sess_key) {

    // NOTE: openssl need middle variable (i2d_X509())

    unsigned char *buf;
    static gquic_tls_client_sess_state_t ins;
    ins.ver = GQUIC_TLS_VERSION_13;
    gquic_list_head_init(&ins.ser_certs);
    gquic_list_head_init(&ins.verified_chain);
    gquic_str_t *ser_cert = gquic_list_alloc(sizeof(gquic_str_t));
    gquic_str_init(ser_cert);
    gquic_list_insert_before(&ins.ser_certs, ser_cert);

    X509 *x509;
    FILE *f = fopen("test_csr.pem", "r");
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    gquic_str_alloc(ser_cert, i2d_X509(x509, NULL));
    buf = GQUIC_STR_VAL(ser_cert);
    i2d_X509(x509, (unsigned char **) &buf);

    gquic_list_insert_before(&ins.verified_chain, gquic_list_alloc(0));

    *state = &ins;
    return 0;
}

int main() {
    /*unsigned char *buf;*/
    /*size_t buf_len;*/
    /*X509 *x509;*/
    /*FILE *f = fopen("test_csr.pem", "r");*/
    /*x509 = PEM_read_X509(f, NULL, NULL, NULL);*/
    /*fclose(f);*/

    /*buf_len = i2d_X509(x509, NULL);*/
    /*i2d_X509(x509, (unsigned char **) &buf);*/

    /*X509 *x;*/
    /*unsigned char *p;*/
    /*int len;*/
    /*p = buf;*/
    /*len = buf_len;*/
    /*x = d2i_X509(NULL, &p, len); */
    /*ERR_print_errors_fp(stdout);*/

    /*char out[255];*/
    /*X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, out, 255);*/
    /*printf("%s\n", out);*/

    /*size_t i; for (i = 0; i < buf_len; i++) printf("%02x ", buf[i]);*/
    /*printf("\n");*/

    /*FILE *opensslder = fopen("fuckder", "r");*/
    /*unsigned char *kbuf = malloc(buf_len);*/
    /*fread(kbuf, buf_len, 1, opensslder);*/
    /*for (i = 0; i < buf_len; i++) printf("%02x ", kbuf[i]);*/
    /*printf("\n");*/

    gquic_tls_client_sess_cache_t cache;
    gquic_tls_ecdhe_params_t ecdhe_param;
    gquic_tls_config_t cfg;
    gquic_tls_conn_t conn;
    gquic_net_addr_t addr;
    gquic_str_t cache_key;
    gquic_str_t early_sec;
    gquic_str_t binder_key;
    gquic_tls_client_sess_state_t *sess;
    gquic_tls_client_hello_msg_t hello;

    cache.get_fptr = _get;
    gquic_net_str_to_addr_v4(&addr, "127.0.0.1");
    gquic_tls_config_init(&cfg);
    GQUIC_STR_VAL(&cfg.ser_name) = "hello";
    GQUIC_STR_SIZE(&cfg.ser_name) = strlen(GQUIC_STR_VAL(&cfg.ser_name));
    cfg.sess_ticket_disabled = 0;
    cfg.cli_sess_cache = &cache;
    cfg.insecure_skiy_verify = 0;
    gquic_tls_conn_init(&conn, &addr, &cfg);
    gquic_str_init(&cache_key);
    gquic_str_init(&early_sec);
    gquic_str_init(&binder_key);
    sess = NULL;
    gquic_tls_client_hello_msg_init(&hello);
    gquic_tls_handshake_client_hello_init(&hello, &conn);
    gquic_tls_handshake_client_hello_edch_params_init(&ecdhe_param, &hello);

    gquic_tls_conn_load_session(&conn, &cache_key, &sess, &early_sec, &binder_key, &hello);

    return 0;
}

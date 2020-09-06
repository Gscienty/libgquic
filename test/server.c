#include "server.h"
#include "unit_test.h"
#include <stdbool.h>

static int get_cert(PKCS12 **const cert_s, const gquic_tls_client_hello_msg_t *const hello) {
    (void) hello;
    FILE *f = fopen("test_certs/ed25519_p12.pem", "r");
    *cert_s = d2i_PKCS12_fp(f, NULL);
    fclose(f);
    return 0;
}

GQUIC_UNIT_TEST(server) {
    gquic_config_t cfg;
    gquic_config_init(&cfg);

    cfg.insecure_skiy_verify = 1;
    cfg.handshake_timeout = 5 * 1000 * 1000;
    cfg.max_idle_timeout = 5 * 1000 * 1000;
    cfg.max_incoming_streams = 5;
    cfg.max_incoming_uni_streams = 5;
    cfg.get_ser_cert = get_cert;

    gquic_server_t ser;
    gquic_server_init(&ser);

    gquic_server_ctor(&ser, gquic_net_addr_v4("127.0.0.1", 4321), &cfg, false);

    gquic_session_t *sess = NULL;

    gquic_server_accept(&sess, &ser);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

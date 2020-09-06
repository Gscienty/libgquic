#include "client.h"
#include "unit_test.h"

GQUIC_UNIT_TEST(client) {
    gquic_config_t cfg;
    gquic_config_init(&cfg);

    cfg.insecure_skiy_verify = true;
    cfg.handshake_timeout = 5 * 1000 * 1000;
    cfg.max_idle_timeout = 5 * 1000 * 1000;
    cfg.max_incoming_streams = 5;
    cfg.max_incoming_uni_streams = 5;

    gquic_client_t cli;
    gquic_client_init(&cli);
    gquic_client_create(&cli, gquic_net_addr_v4("127.0.0.1", 1234), gquic_net_addr_v4("127.0.0.1", 4321), &cfg);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

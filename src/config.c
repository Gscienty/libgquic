#include "config.h"
#include "exception.h"

int gquic_config_init(gquic_config_t *const config) {
    if (config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&config->versions);
    config->conn_id_len = 0;
    config->handshake_timeout = 0;
    config->max_idle_timeout = 0;
    config->max_recv_stream_flow_ctrl_wnd = 0;
    config->max_recv_conn_flow_ctrl_wnd = 0;
    config->max_incoming_uni_streams = 0;
    config->max_incoming_streams = 0;
    gquic_str_init(&config->stateless_reset_key);
    config->keep_alive = 1;

    gquic_list_head_init(&config->next_protos);
    config->enforce_next_proto_selections = 0;
    config->verify_peer_certs = NULL;
    config->get_ser_cert = NULL;
    config->get_cli_cert = NULL;
    gquic_list_head_init(&config->cipher_suites);
    config->ser_perfer_cipher_suite  = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

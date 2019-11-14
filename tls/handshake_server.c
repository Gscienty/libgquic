#include "tls/handshake_server.h"

static int gquic_tls_handshake_server_state_process_cli_hello(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_check_for_resumption(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_pick_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_params(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_send_ser_finished(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_read_cli_cert(gquic_tls_handshake_server_state_t *const);
static int gquic_tls_handshake_server_state_read_cli_finished(gquic_tls_handshake_server_state_t *const);

int gquic_tls_handshake_sever_state_init(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }

    ser_state->conn = NULL;
    ser_state->c_hello = NULL;
    ser_state->s_hello = NULL;
    ser_state->sent_dummy_ccs = 0;
    ser_state->using_psk = 0;
    ser_state->suite = NULL;
    gquic_str_init(&ser_state->cert);
    ser_state->sigalg = 0;
    gquic_str_init(&ser_state->early_sec);
    gquic_str_init(&ser_state->shared_key);
    gquic_str_init(&ser_state->handshake_sec);
    gquic_str_init(&ser_state->master_sec);
    gquic_str_init(&ser_state->traffic_sec);
    gquic_tls_mac_init(&ser_state->transport);
    gquic_str_init(&ser_state->cli_finished);

    return 0;
}

int gquic_tls_handshake_server_state_release(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }
    if (ser_state->c_hello != NULL) {
        gquic_tls_client_hello_msg_reset(ser_state->c_hello);
        free(ser_state->c_hello);
    }
    if (ser_state->s_hello != NULL) {
        gquic_tls_server_hello_msg_reset(ser_state->s_hello);
        free(ser_state->s_hello);
    }
    gquic_str_reset(&ser_state->cert);
    gquic_str_reset(&ser_state->early_sec);
    gquic_str_reset(&ser_state->shared_key);
    gquic_str_reset(&ser_state->handshake_sec);
    gquic_str_reset(&ser_state->master_sec);
    gquic_str_reset(&ser_state->traffic_sec);
    gquic_tls_mac_release(&ser_state->transport);
    gquic_str_reset(&ser_state->cli_finished);
    return 0;
}

int gquic_tls_server_handshake(gquic_tls_conn_t *const conn) {
    u_int8_t handshake_type = 0;
    gquic_tls_handshake_server_state_t ser_state;
    if (conn == NULL) {
        return -1;
    }
    gquic_tls_handshake_server_state_init(&ser_state);
    ser_state.conn = conn;
    if (gquic_tls_conn_set_alt_record(conn) != 0) {
        return -2;
    }
    if (gquic_tls_conn_read_handshake(&handshake_type, (void **) &ser_state.c_hello, conn) != 0) {
        return -3;
    }
    if (handshake_type != GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO) {
        gquic_tls_common_handshake_record_release(GQUIC_TLS_VERSION_13, handshake_type, ser_state.c_hello);
        return -4;
    }
    if (gquic_tls_server_handshake_state_handshake(&ser_state) != 0) {
        gquic_tls_handshake_server_state_release(&ser_state);
        return -5;
    }
    
    gquic_tls_handshake_server_state_release(&ser_state);
    return 0;
}

int gquic_tls_server_handshake_state_handshake(gquic_tls_handshake_server_state_t *const ser_state) {
    if (ser_state == NULL) {
        return -1;
    }

    if (gquic_tls_handshake_server_state_process_cli_hello(ser_state) != 0) {
        return -2;
    }
    if (gquic_tls_handshake_server_state_check_for_resumption(ser_state) != 0) {
        return -3;
    }
    if (gquic_tls_handshake_server_state_pick_cert(ser_state) != 0) {
        return -4;
    }
    ser_state->conn->buffering = 1;
    if (gquic_tls_handshake_server_state_send_ser_params(ser_state) != 0) {
        return -5;
    }
    if (gquic_tls_handshake_server_state_send_ser_cert(ser_state) != 0) {
        return -6;
    }
    if (gquic_tls_handshake_server_state_send_ser_finished(ser_state) != 0) {
        return -7;
    }
    if (gquic_tls_handshake_server_state_read_cli_cert(ser_state) != 0) {
        return -8;
    }
    if (gquic_tls_handshake_server_state_read_cli_finished(ser_state) != 0) {
        return -9;
    }

    ser_state->conn->handshake_status = 1;

    return 0;
}

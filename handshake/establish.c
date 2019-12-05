#include "handshake/establish.h"

int gquic_handshake_event_init(gquic_handshake_event_t *const event) {
    if (event == NULL) {
        return -1;
    }
    event->self = NULL;
    event->on_recv_params = NULL;
    event->on_err = NULL;
    event->drop_keys = NULL;
    event->on_handshake_complete = NULL;

    return 0;
}

int gquic_handshake_establish_init(gquic_handshake_establish_t *const est) {
    if (est == NULL) {
        return -1;
    }

    gquic_tls_config_init(&est->cfg);
    gquic_tls_conn_init(&est->conn);
    gquic_handshake_event_init(&est->events);
    gquic_sem_list_init(&est->msg_p);
    gquic_sem_list_init(&est->params_p);
    gquic_sem_list_init(&est->alert_p);
    sem_init(&est->handshake_done_sem, 0, 0);
    sem_init(&est->close_sem, 0, 0);
    est->cli_hello_written = 0;
    sem_init(&est->cli_hello_written_sem, 0, 0);
    sem_init(&est->recv_wkey_sem, 0, 0);
    sem_init(&est->recv_rkey_sem, 0, 0);
    sem_init(&est->write_record_sem, 0, 0);
    est->is_client = 0;
    sem_init(&est->mtx, 0, 1);
    est->read_enc_level = 0;
    est->write_enc_level = 0;
    gquic_io_init(&est->init_output);
    gquic_handshake_opener_init(&est->init_opener);
    gquic_handshake_sealer_init(&est->init_sealer);
    gquic_io_init(&est->handshake_output);
    gquic_handshake_opener_init(&est->handshake_opener);
    gquic_handshake_sealer_init(&est->handshake_sealer);
    gquic_io_init(&est->one_rtt_output);
    gquic_auto_update_aead_init(&est->aead);
    est->has_1rtt_sealer = 0;
    est->has_1rtt_opener = 0;

    return 0;
}

#include "tls/ticket.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include <stddef.h>

int gquic_tls_sess_state_init(gquic_tls_sess_state_t *const state) {
    if (state == NULL) {
        return -1;
    }
    state->cipher_suite = 0;
    state->create_at = 0;
    gquic_str_init(&state->resumption_sec);
    gquic_tls_cert_init(&state->cert);

    return 0;
}

int gquic_tls_sess_state_dtor(gquic_tls_sess_state_t *const state) {
    if (state == NULL) {
        return -1;
    }
    gquic_str_reset(&state->resumption_sec);
    gquic_tls_cert_dtor(&state->cert);

    return 0;
}

ssize_t gquic_tls_sess_state_size(const gquic_tls_sess_state_t *const state) {
    size_t ret = 0;
    if (state == NULL) {
        return -1;
    }
    ret += 2 + 1 + 2 + 8 + 1 + GQUIC_STR_SIZE(&state->resumption_sec) + gquic_tls_cert_size(&state->cert);
    return ret;
}

int gquic_tls_sess_state_serialize(const gquic_tls_sess_state_t *const state, gquic_writer_str_t *const writer) {
    size_t ret = 0;
    if (state == NULL || writer == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_sess_state_size(state) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_big_endian_writer_2byte(writer, GQUIC_TLS_VERSION_13);
    gquic_big_endian_writer_1byte(writer, 0);
    gquic_big_endian_writer_2byte(writer, state->cipher_suite);
    gquic_big_endian_writer_8byte(writer, state->create_at);
    __gquic_fill_str(writer, &state->resumption_sec, 1);
    gquic_tls_cert_serialize(&state->cert, writer);

    return ret;
}

int gquic_tls_sess_state_deserialize(gquic_tls_sess_state_t *const state, gquic_reader_str_t *const reader) {
    size_t ret = 0;
    if (state == NULL || reader == NULL) {
        return -1;
    }
    gquic_reader_str_readed_size(reader, 3);
    if (__gquic_recovery_bytes(&state->cipher_suite, 2, reader) != 0) {
        return -2;
    }
    if (__gquic_recovery_bytes(&state->create_at, 8, reader) != 0) {
        return -3;
    }
    if (__gquic_recovery_str(&state->resumption_sec, 1, reader) != 0) {
        return -4;
    }
    if (gquic_tls_cert_deserialize(&state->cert, reader) != 0) {
        return -5;
    }

    return ret;
}

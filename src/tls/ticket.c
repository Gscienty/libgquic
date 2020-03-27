#include "tls/ticket.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "tls/common.h"
#include <stddef.h>

int gquic_tls_sess_state_init(gquic_tls_sess_state_t *const state) {
    if (state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    state->cipher_suite = 0;
    state->create_at = 0;
    gquic_str_init(&state->resumption_sec);
    gquic_tls_cert_init(&state->cert);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_sess_state_dtor(gquic_tls_sess_state_t *const state) {
    if (state == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&state->resumption_sec);
    gquic_tls_cert_dtor(&state->cert);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

ssize_t gquic_tls_sess_state_size(const gquic_tls_sess_state_t *const state) {
    if (state == NULL) {
        return 0;
    }
    return 2 + 1 + 2 + 8 + 1 + GQUIC_STR_SIZE(&state->resumption_sec) + gquic_tls_cert_size(&state->cert);
}

int gquic_tls_sess_state_serialize(const gquic_tls_sess_state_t *const state, gquic_writer_str_t *const writer) {
    if (state == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((size_t) gquic_tls_sess_state_size(state) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_big_endian_writer_2byte(writer, GQUIC_TLS_VERSION_13);
    gquic_big_endian_writer_1byte(writer, 0);
    gquic_big_endian_writer_2byte(writer, state->cipher_suite);
    gquic_big_endian_writer_8byte(writer, state->create_at);
    __gquic_fill_str(writer, &state->resumption_sec, 1);
    gquic_tls_cert_serialize(&state->cert, writer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_tls_sess_state_deserialize(gquic_tls_sess_state_t *const state, gquic_reader_str_t *const reader) {
    if (state == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_reader_str_readed_size(reader, 3);
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&state->cipher_suite, 2, reader));
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&state->create_at, 8, reader));
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_str(&state->resumption_sec, 1, reader));
    GQUIC_ASSERT_FAST_RETURN(gquic_tls_cert_deserialize(&state->cert, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

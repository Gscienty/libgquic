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

ssize_t gquic_tls_sess_state_serialize(const gquic_tls_sess_state_t *const state, void *const buf, const size_t size) {
    size_t ret = 0;
    size_t off = 0;
    if (state == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_tls_sess_state_size(state) > size) {
        return -2;
    }
    __gquic_fill_2byte(buf, &off, GQUIC_TLS_VERSION_13);
    __gquic_fill_1byte(buf, &off, 0);
    __gquic_fill_2byte(buf, &off, state->cipher_suite);
    __gquic_fill_8byte(buf, &off, state->create_at);
    __gquic_fill_str_full(buf, &off, &state->resumption_sec, 1);
    gquic_tls_cert_serialize(&state->cert, buf + off, size - off);

    return ret;
}

ssize_t gquic_tls_sess_state_deserialize(gquic_tls_sess_state_t *const state, const void *const buf, const size_t size) {
    size_t ret = 0;
    size_t off = 0;
    if (state == NULL || buf == NULL) {
        return -1;
    }
    off += 3;
    if (__gquic_recovery_bytes(&state->cipher_suite, 2, buf, size, &off) != 0) {
        return -2;
    }
    if (__gquic_recovery_bytes(&state->create_at, 8, buf, size, &off) != 0) {
        return -3;
    }
    if (__gquic_recovery_str_full(&state->resumption_sec, 1, buf, size, &off) != 0) {
        return -4;
    }
    if (gquic_tls_cert_deserialize(&state->cert, buf + off, size - off) != 0) {
        return -5;
    }

    return ret;
}

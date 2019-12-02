#include "handshake/transport_parameters.h"
#include "util/varint.h"
#include <stddef.h>

size_t gquic_transport_parameters_size(const gquic_transport_parameters_t *const params) {
    size_t ret = 0;
    if (params == NULL) {
        return 0;
    }
    ret += 2 + 2 + 16;

    ret += 2 + 2 + gquic_varint_size(&params->init_max_data);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_uni);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_bidi_local);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_bidi_remote);
    ret += 2 + 2 + gquic_varint_size(&params->max_streams_uni);
    ret += 2 + 2 + gquic_varint_size(&params->max_streams_bidi);
    ret += 2 + 2 + gquic_varint_size(&params->idle_timeout);
    ret += 2 + 2 + gquic_varint_size(&params->max_packet_size);
    if (params->max_ack_delay > 25 * 1000) {
        u_int64_t tmp = params->max_ack_delay / 1000;
        ret += 2 + 2 + gquic_varint_size(&tmp);
    }
    if (params->ack_delay_exponent > 3) {
        u_int64_t tmp = params->ack_delay_exponent;
        ret += 2 + 2 + gquic_varint_size(&tmp);
    }
    if (params->disable_migration) {
        ret += 2 + 2;
    }
    if (GQUIC_STR_SIZE(&params->stateless_reset_token) != 0) {
        ret += 2 + 2 + GQUIC_STR_SIZE(&params->stateless_reset_token);
    }
    if (GQUIC_STR_SIZE(&params->original_conn_id) != 0) {
        ret += 2 + 2 + GQUIC_STR_SIZE(&params->original_conn_id);
    }
    ret += 2 + 2 + gquic_varint_size(&params->active_conn_id_limit);
    return ret;
}

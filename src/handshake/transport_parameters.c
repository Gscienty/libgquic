#include "handshake/transport_parameters.h"
#include "util/varint.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include "exception.h"
#include <stddef.h>
#include <openssl/rand.h>

static inline gquic_exception_t __serialize_var(gquic_writer_str_t *const writer,
                                                gquic_list_t *const prefix_len_stack, const u_int16_t id, const u_int64_t val);

gquic_exception_t gquic_transport_parameters_init(gquic_transport_parameters_t *const params) {
    if (params == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_init(&params->original_conn_id);
    params->idle_timeout = 0;
    gquic_str_init(&params->stateless_reset_token);
    params->max_packet_size = 0;
    params->init_max_data = 0;
    params->init_max_stream_data_bidi_local = 0;
    params->init_max_stream_data_bidi_remote = 0;
    params->init_max_stream_data_uni = 0;
    params->max_streams_bidi = 0;
    params->max_streams_uni = 0;
    params->ack_delay_exponent = 3;
    params->max_ack_delay = 25 * 1000;
    params->disable_migration = true;
    params->active_conn_id_limit = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

size_t gquic_transport_parameters_size(const gquic_transport_parameters_t *const params) {
    size_t ret = 0;
    if (params == NULL) {
        return 0;
    }
    ret += 2;
    ret += 2 + 2 + gquic_varint_size(&params->init_max_data);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_uni);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_bidi_local);
    ret += 2 + 2 + gquic_varint_size(&params->init_max_stream_data_bidi_remote);
    ret += 2 + 2 + gquic_varint_size(&params->max_streams_uni);
    ret += 2 + 2 + gquic_varint_size(&params->max_streams_bidi);
    ret += 2 + 2 + gquic_varint_size(&params->idle_timeout);
    ret += 2 + 2 + gquic_varint_size(&params->max_packet_size);
    if (params->max_ack_delay != 25 * 1000) {
        u_int64_t tmp = params->max_ack_delay / 1000;
        ret += 2 + 2 + gquic_varint_size(&tmp);
    }
    if (params->ack_delay_exponent != 3) {
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

gquic_exception_t gquic_transport_parameters_serialize(const gquic_transport_parameters_t *const params, gquic_writer_str_t *const writer) {
    gquic_list_t prefix_len_stack;
    if (params == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    
    gquic_list_head_init(&prefix_len_stack);
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(&prefix_len_stack, writer, 2));

    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA, params->init_max_data));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, params->init_max_stream_data_bidi_local));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, params->init_max_stream_data_bidi_remote));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI, params->init_max_stream_data_uni));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI, params->max_streams_bidi));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI, params->max_streams_uni));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_IDLE_TIMEOUT, params->idle_timeout));
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_MAX_PACKET_SIZE, params->max_packet_size));
    if (params->max_ack_delay != 25 * 1000) {
        GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                                 GQUIC_TRANSPORT_PARAM_MAX_ACK_DELAY, params->max_ack_delay / 1000));
    }
    if (params->ack_delay_exponent != 3) {
        GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                                 GQUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT, params->ack_delay_exponent));
    }
    if (params->disable_migration) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TRANSPORT_PARAM_DISABLE_MIGRATION));
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, 0));
    }
    if (GQUIC_STR_SIZE(&params->stateless_reset_token) != 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &params->stateless_reset_token, 2));
    }
    if (GQUIC_STR_SIZE(&params->original_conn_id) != 0) {
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, GQUIC_TRANSPORT_PARAM_ORIGINAL_CONNID));
        GQUIC_ASSERT_FAST_RETURN(__gquic_fill_str(writer, &params->original_conn_id, 2));
    }
    GQUIC_ASSERT_FAST_RETURN(__serialize_var(writer, &prefix_len_stack,
                                             GQUIC_TRANSPORT_PARAM_ACTIVE_CONN_ID_LIMIT, params->active_conn_id_limit));

    gquic_str_t tmp_writer = *writer;
    tmp_writer.val -= 2;
    tmp_writer.size += 2;
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(&prefix_len_stack, &tmp_writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_transport_parameters_deserialize(gquic_transport_parameters_t *const params, gquic_reader_str_t *const reader) {
    size_t len = 0;
    u_int16_t id = 0;
    u_int16_t param_len = 0;
    if (params == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&len, 2, reader));
    if (len > GQUIC_STR_SIZE(reader) - 2) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_reader_str_t inner_reader = { len, GQUIC_STR_VAL(reader) };
    while (GQUIC_STR_SIZE(&inner_reader) >= 4) {
        id = 0;
        param_len = 0;
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&id, 2, &inner_reader));
        GQUIC_ASSERT_FAST_RETURN(__gquic_recovery_bytes(&param_len, 2, &inner_reader));
        switch (id) {
        case GQUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize((u_int64_t *) &params->ack_delay_exponent, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_MAX_ACK_DELAY:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->max_ack_delay, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->init_max_data, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->max_streams_uni, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->max_streams_bidi, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->init_max_stream_data_uni, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->init_max_stream_data_bidi_local, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->init_max_stream_data_bidi_remote, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_IDLE_TIMEOUT:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->idle_timeout, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_MAX_PACKET_SIZE:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->max_packet_size, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_ACTIVE_CONN_ID_LIMIT:
            GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&params->active_conn_id_limit, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_DISABLE_MIGRATION:
            params->disable_migration = true;
            break;
        case GQUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
            GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&params->stateless_reset_token, param_len));
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&params->stateless_reset_token, &inner_reader));
            break;
        case GQUIC_TRANSPORT_PARAM_ORIGINAL_CONNID:
            GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&params->original_conn_id, param_len));
            GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&params->original_conn_id, &inner_reader));
            break;
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static inline gquic_exception_t __serialize_var(gquic_writer_str_t *const writer,
                                  gquic_list_t *const prefix_len_stack, const u_int16_t id, const u_int64_t val) {
    if (writer == NULL || prefix_len_stack == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, id));
    GQUIC_ASSERT_FAST_RETURN(__gquic_store_prefix_len(prefix_len_stack, writer, 2));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&val, writer));
    GQUIC_ASSERT_FAST_RETURN(__gquic_fill_prefix_len(prefix_len_stack, writer));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#include "handshake/transport_parameters.h"
#include "util/varint.h"
#include "tls/_msg_serialize_util.h"
#include "tls/_msg_deserialize_util.h"
#include <stddef.h>
#include <openssl/rand.h>

static inline int __serialize_var(void *const, size_t *const, const size_t, gquic_list_t *const, const u_int16_t, const u_int64_t);

int gquic_transport_parameters_init(gquic_transport_parameters_t *const params) {
    if (params == NULL) {
        return -1;
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
    params->disable_migration = 1;
    params->active_conn_id_limit = 0;

    return 0;
}

size_t gquic_transport_parameters_size(const gquic_transport_parameters_t *const params) {
    size_t ret = 0;
    if (params == NULL) {
        return 0;
    }
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

ssize_t gquic_transport_parameters_serialize(const gquic_transport_parameters_t *const params, void *const buf, const size_t size) {
    size_t off = 0;
    gquic_list_t prefix_len_stack;
    if (params == NULL || buf == NULL) {
        return -1;
    }
    
    gquic_list_head_init(&prefix_len_stack);
    __gquic_store_prefix_len(&prefix_len_stack, &off, 2);

    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, params->init_max_stream_data_bidi_local);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, params->init_max_stream_data_bidi_remote);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI, params->init_max_stream_data_uni);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA, params->init_max_data);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI, params->max_streams_bidi);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI, params->max_streams_uni);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_IDLE_TIMEOUT, params->idle_timeout);
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_MAX_PACKET_SIZE, params->max_packet_size);
    if (params->max_ack_delay != 25 * 1000) {
        __serialize_var(buf, &off, size, &prefix_len_stack,
                        GQUIC_TRANSPORT_PARAM_MAX_ACK_DELAY, params->max_ack_delay / 1000);
    }
    if (params->ack_delay_exponent != 3) {
        __serialize_var(buf, &off, size, &prefix_len_stack,
                        GQUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT, params->ack_delay_exponent);
    }
    if (params->disable_migration) {
        __gquic_fill_2byte(buf, &off, GQUIC_TRANSPORT_PARAM_DISABLE_MIGRATION);
        __gquic_fill_2byte(buf, &off, 0);
    }
    if (GQUIC_STR_SIZE(&params->stateless_reset_token) != 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
        __gquic_fill_str_full(buf, &off, &params->stateless_reset_token, 2);
    }
    if (GQUIC_STR_SIZE(&params->original_conn_id) != 0) {
        __gquic_fill_2byte(buf, &off, GQUIC_TRANSPORT_PARAM_ORIGINAL_CONNID);
        __gquic_fill_str_full(buf, &off, &params->original_conn_id, 2);
    }
    __serialize_var(buf, &off, size, &prefix_len_stack,
                    GQUIC_TRANSPORT_PARAM_ACTIVE_CONN_ID_LIMIT, params->active_conn_id_limit);

    __gquic_fill_prefix_len(&prefix_len_stack, buf, off, 2);
    return off;
}

ssize_t gquic_transport_parameters_deserialize(gquic_transport_parameters_t *const params, const void *const buf, const size_t size) {
    size_t off = 0;
    size_t len = 0;
    ssize_t varint_len = 0;
    u_int16_t id = 0;
    u_int16_t param_len = 0;
    gquic_str_t tmp = { 0, NULL };
    if (params == NULL || buf == NULL) {
        return -1;
    }
    __gquic_recovery_bytes(&len, 2, buf, size, &off);
    if (len > size - 2) {
        return -2;
    }
    while (off < 2 + len) {
        id = 0;
        param_len = 0;
        varint_len = 0;
        __gquic_recovery_bytes(&id, 2, buf, size, &off);
        __gquic_recovery_bytes(&param_len, 2, buf, size, &off);
        switch (id) {
        case GQUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
            if ((varint_len = gquic_varint_deserialize((u_int64_t *) &params->ack_delay_exponent, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_MAX_ACK_DELAY:
            if ((varint_len = gquic_varint_deserialize(&params->max_ack_delay, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
            if ((varint_len = gquic_varint_deserialize(&params->init_max_data, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
            if ((varint_len = gquic_varint_deserialize(&params->max_streams_uni, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
            if ((varint_len = gquic_varint_deserialize(&params->max_streams_bidi, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
            if ((varint_len = gquic_varint_deserialize(&params->init_max_stream_data_uni, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            if ((varint_len = gquic_varint_deserialize(&params->init_max_stream_data_bidi_local, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            if ((varint_len = gquic_varint_deserialize(&params->init_max_stream_data_bidi_remote, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_IDLE_TIMEOUT:
            if ((varint_len = gquic_varint_deserialize(&params->idle_timeout, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_MAX_PACKET_SIZE:
            if ((varint_len = gquic_varint_deserialize(&params->max_packet_size, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_ACTIVE_CONN_ID_LIMIT:
            if ((varint_len = gquic_varint_deserialize(&params->active_conn_id_limit, buf + off, size)) <= 0) {
                return -3;
            }
            off += varint_len;
            break;
        case GQUIC_TRANSPORT_PARAM_DISABLE_MIGRATION:
            params->disable_migration = 1;
            break;
        case GQUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
            tmp.size = param_len;
            tmp.val = (void *) buf + off;
            if (gquic_str_copy(&params->stateless_reset_token, &tmp) != 0) {
                return -3;
            }
            break;
        case GQUIC_TRANSPORT_PARAM_ORIGINAL_CONNID:
            tmp.size = param_len;
            tmp.val = (void *) buf + off;
            if (gquic_str_copy(&params->original_conn_id, &tmp) != 0) {
                return -3;
            }
            break;
        }
    }

    return 0;
}

static inline int __serialize_var(void *const buf,
                                  size_t *const off,
                                  const size_t size,
                                  gquic_list_t *const prefix_len_stack,
                                  const u_int16_t id,
                                  const u_int64_t val) {
    ssize_t ret = 0;
    if (buf == NULL || off == NULL || prefix_len_stack == NULL) {
        return -1;
    }
    __gquic_fill_2byte(buf, off, id);
    __gquic_store_prefix_len(prefix_len_stack, off, 2);
    if ((ret = gquic_varint_serialize(&val, buf + (*off), size - *off)) <= 0) {
        return -2;
    }
    *off += ret;
    __gquic_fill_prefix_len(prefix_len_stack, buf, *off, 2);
    return 0;
}

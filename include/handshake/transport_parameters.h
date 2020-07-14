/* include/handshake/transport_parameters.h TLS extensions transport parameters
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_TRANSPORT_PARAMETERS_H
#define _LIBGQUIC_HANDSHAKE_TRANSPORT_PARAMETERS_H

#include <sys/types.h>
#include "util/str.h"
#include "exception.h"
#include <stdbool.h>

#define GQUIC_TRANSPORT_PARAM_ORIGINAL_CONNID 0x00
#define GQUIC_TRANSPORT_PARAM_IDLE_TIMEOUT 0x01
#define GQUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN 0x02
#define GQUIC_TRANSPORT_PARAM_MAX_PACKET_SIZE 0x03
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA 0x04
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x05
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI 0x07
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI 0x08
#define GQUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI 0x09
#define GQUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT 0x0a
#define GQUIC_TRANSPORT_PARAM_MAX_ACK_DELAY 0x0b
#define GQUIC_TRANSPORT_PARAM_DISABLE_MIGRATION 0x0c
#define GQUIC_TRANSPORT_PARAM_ACTIVE_CONN_ID_LIMIT 0x0e


typedef struct gquic_transport_parameters_s gquic_transport_parameters_t;
struct gquic_transport_parameters_s {
    gquic_str_t original_conn_id;
    u_int64_t idle_timeout;
    gquic_str_t stateless_reset_token;
    u_int64_t max_packet_size;
    u_int64_t init_max_data;
    u_int64_t init_max_stream_data_bidi_local;
    u_int64_t init_max_stream_data_bidi_remote;
    u_int64_t init_max_stream_data_uni;
    u_int64_t max_streams_bidi;
    u_int64_t max_streams_uni;
    u_int8_t ack_delay_exponent;
    u_int64_t max_ack_delay;
    bool disable_migration;
    u_int64_t active_conn_id_limit;
};

/**
 * 初始化transport parameters
 * 
 * @param params: transport parameters
 * 
 * @return: exception
 */
gquic_exception_t gquic_transport_parameters_init(gquic_transport_parameters_t *const params);

/**
 * 获取transport parameters序列化后的长度
 *
 * @param params: transport parameters
 * 
 * @return: transport parameters序列化后的长度
 */
size_t gquic_transport_parameters_size(const gquic_transport_parameters_t *const params);

/**
 * transport parameters序列化
 *
 * @param params: transport parameters
 * @param writer: writer
 *
 * @return: exception
 */
gquic_exception_t gquic_transport_parameters_serialize(const gquic_transport_parameters_t *const params, gquic_writer_str_t *const writer);

/**
 * transport parameters反序列化
 *
 * @param params: transport parameters
 * @param reader: reader
 * 
 * @return: exception
 */
gquic_exception_t gquic_transport_parameters_deserialize(gquic_transport_parameters_t *const params, gquic_reader_str_t *const reader);

#endif

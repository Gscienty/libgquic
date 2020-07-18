/* include/packet/long_header_packet.h 长首部
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H
#define _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H

#include "packet_number.h"
#include "util/version.h"
#include "util/varint.h"

/**
 * 通用长首部部分
 */
typedef struct gquic_packet_long_header_s gquic_packet_long_header_t;
struct gquic_packet_long_header_s {
    u_int8_t flag;
    gquic_version_t version;
    u_int8_t dcid_len;
    u_int8_t dcid[20];
    u_int8_t scid_len;
    u_int8_t scid[20];
};

/**
 * INITIAL长首部
 */
typedef struct gquic_packet_initial_header_s gquic_packet_initial_header_t;
struct gquic_packet_initial_header_s {
    u_int64_t token_len;
    void *token;
    u_int64_t len;
    u_int64_t pn;
};

/**
 * 0RTT长首部
 */
typedef struct gquic_packet_0rtt_header_s gquic_packet_0rtt_header_t;
struct gquic_packet_0rtt_header_s {
    u_int64_t len;
    u_int64_t pn;
};

/**
 * HANDSHAKE长首部
 */
typedef struct gquic_packet_handshake_header_s gquic_packet_handshake_header_t;
struct gquic_packet_handshake_header_s {
    u_int64_t len;
    u_int64_t pn;
};

/**
 * RETRY长首部
 */
typedef struct gquic_packet_retry_header_s gquic_packet_retry_header_t;
struct gquic_packet_retry_header_s {
    unsigned char odcid_len;
    unsigned char odcid[20];
};


/**
 * 从通用长首部获取具体的长首部字段
 *
 * @param t: 返回的指针类型
 * @param h: 长首部
 *
 * @return: 具体的长首部
 */
#define GQUIC_LONG_HEADER_SPEC(t, h) ((t *) (((void *) (h)) + sizeof(gquic_packet_long_header_t)))

/**
 * 从具体长首部获取通用长首部
 *
 * @param h: 具体长首部
 */
#define GQUIC_LONG_HEADER_COMMON(h) (*((gquic_packet_long_header_t *) (((void *) (h)) - sizeof(gquic_packet_long_header_t))))

/**
 * 生成长首部
 *
 * @return header_storage: 长首部
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_alloc(gquic_packet_long_header_t **const header_storage);

/**
 * 释放长首部
 *
 * @param header: 长首部
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_release(gquic_packet_long_header_t *const header);

/**
 * 获取长首部的长度
 *
 * @param header: 长首部
 *
 * @return: 长首部的长度
 */
size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *const header);

/**
 * 长首部序列化
 *
 * @param header: 长首部
 * @param writer: writer
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_serialize(const gquic_packet_long_header_t *const header, gquic_writer_str_t *const writer);

/**
 * 长首部反序列化
 *
 * @param header: 长首部
 * @param reader: reader
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_deserialize(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader);

/**
 * 长首部反序列化未加密部分
 *
 * @param header: 长首部
 * @param reader: reader
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_deserialize_unseal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader);

/**
 * 长首部反序列化加密部分
 *
 * @param header: 长首部
 * @param reader: reader
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_long_header_deserialize_seal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader);

#define GQUIC_LONG_HEADER_INITIAL 0x01
#define GQUIC_LONG_HEADER_0RTT 0x02
#define GQUIC_LONG_HEADER_HANDSHAKE 0x03
#define GQUIC_LONG_HEADER_RETRY 0x04

/**
 * 获取长首部的具体类型
 *
 * @param header: 长首部
 *
 * @return: 具体类型
 */
u_int8_t gquic_packet_long_header_type(const gquic_packet_long_header_t *const header);

#endif

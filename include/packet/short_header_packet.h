/* include/packet/short_header_packet.h 短首部
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_SHORT_HEADER_PACKET_H
#define _LIBGQUIC_PACKET_SHORT_HEADER_PACKET_H

#include "util/str.h"
#include "exception.h"
#include <sys/types.h>

/**
 * 短首部
 */
typedef struct gquic_packet_short_header_s gquic_packet_short_header_t;
struct gquic_packet_short_header_s {
    u_int8_t flag;
    u_int8_t dcid_len;
    u_int8_t dcid[20];
    u_int64_t pn;
};

/**
 * 生成短首部
 *
 * @return header_storage: 短首部
 * @return: exception
 */
gquic_exception_t gquic_packet_short_header_alloc(gquic_packet_short_header_t **const header_storage);

/**
 * 获取短首部长度
 *
 * @param header: 短首部
 *
 * @return: 短首部长度
 */
ssize_t gquic_packet_short_header_size(const gquic_packet_short_header_t *const header);

/**
 * 短首部序列化操作
 *
 * @param header: 短首部
 * @param writer: writer
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_short_header_serialize(const gquic_packet_short_header_t *const header, gquic_writer_str_t *const writer);

/**
 * 短首部反序列化操作
 *
 * @param header: 短首部
 * @param reader: reader
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_short_header_deserialize(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader);

/**
 * 短首部反序列化未加密部分
 *
 * @param header: 短首部
 * @param reader: reader
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_short_header_deserialize_unseal_part(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader);

/**
 * 短首部反序列化加密部分
 *
 * @param header: 短首部
 * @param reader: reader
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_short_header_deserialize_seal_part(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader);

#define GQUIC_SHORT_HEADER 0x05

#endif

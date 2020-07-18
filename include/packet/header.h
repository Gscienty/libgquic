/* include/packet/header.h packet header 封装
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_HEADER_H
#define _LIBGQUIC_PACKET_HEADER_H

#include "packet/long_header_packet.h"
#include "packet/short_header_packet.h"
#include "exception.h"
#include <stdbool.h>

/**
 * 通用packet头部
 */
typedef struct gquic_packet_header_s gquic_packet_header_t;
struct gquic_packet_header_s {
    bool is_long;
    union {
        gquic_packet_long_header_t *l_hdr;
        gquic_packet_short_header_t *s_hdr;
    } hdr;
};

/**
 * 初始化通用packet头部
 *
 * @param header: 通用packet头部
 * 
 * @return: exception
 */
gquic_exception_t gquic_packet_header_init(gquic_packet_header_t *const header);

/**
 * 析构通用packet头部
 *
 * @param header: 通用packet头部
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_dtor(gquic_packet_header_t *const header);

/**
 * 从packet头部获取packet number
 *
 * @param header: 通用packet头部
 *
 * @return: packet number
 */
u_int64_t gquic_packet_header_get_pn(gquic_packet_header_t *const header);

/**
 * 设置packet头部的packet number
 *
 * @param header: 通用packet头部
 * @param pn: packet number
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_set_pn(gquic_packet_header_t *const header, const u_int64_t pn);

/**
 * 设置packet头部的payload长度
 *
 * @param header: 通用header头部
 * @param len: payload长度
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_set_len(gquic_packet_header_t *const header, const u_int64_t len);

/**
 * 获取packet头部的长度
 *
 * @param header: 通用header头部
 *
 * @return: 头部的长度
 */
size_t gquic_packet_header_size(gquic_packet_header_t *const header);

/**
 * 从raw中获取connection id
 * 
 * @param conn_id: connection id
 * @param data: 原始raw
 * @param conn_id_len: connection id长度
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_deserialize_conn_id(gquic_str_t *const conn_id, const gquic_str_t *const data, const int conn_id_len);

/**
 * 从raw中获取源connection id
 * 
 * @param conn_id: connection id
 * @param data: 原始raw
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_deserialize_src_conn_id(gquic_str_t *const conn_id, const gquic_str_t *const data);

/**
 * 从raw中获取packet长度
 * 
 * @param packet_len: packet长度
 * @param data: 原始raw
 * @param conn_id_len: connection id长度
 *
 * @return: exception
 */
gquic_exception_t gquic_packet_header_deserialize_packet_len(u_int64_t *const packet_len, const gquic_str_t *const data, const int conn_id_len);

/**
 * 从raw中获取packet类型
 * 
 * @param data: 原始raw
 *
 * @return: packet类型
 */
u_int8_t gquic_packet_header_deserlialize_type(const gquic_str_t *const data);

/**
 * 从通用packet头部中获得长头部
 *
 * @param header: 通用packet头部
 * 
 * @return: 长头部
 */
static inline gquic_packet_long_header_t *gquic_packet_header_long(gquic_packet_header_t *const header) {
    if (header == NULL) {
        return NULL;
    }
    if (!header->is_long) {
        return NULL;
    }

    return header->hdr.l_hdr;
}

/**
 * 从通用packet头部中获得短头部
 *
 * @param header: 通用packet头部
 * 
 * @return: 短头部
 */
static inline gquic_packet_short_header_t *gquic_packet_header_short(gquic_packet_header_t *const header) {
    if (header == NULL) {
        return NULL;
    }
    if (header->is_long) {
        return NULL;
    }

    return header->hdr.s_hdr;
}

#endif

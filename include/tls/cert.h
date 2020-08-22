/* include/tls/cert.h TLS record 证书实体
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CERT_H
#define _LIBGQUIC_TLS_CERT_H

#include "util/str.h"
#include "util/list.h"
#include "exception.h"

/**
 * 证书实体
 */
typedef struct gquic_tls_cert_s gquic_tls_cert_t;
struct gquic_tls_cert_s {

    // 证书列表
    gquic_list_t certs; /* X509 * */

    // Online Certificate Status Protocol
    gquic_str_t ocsp_staple;

    // Signed Certificate Timestamp
    gquic_list_t scts;
};

/**
 * 初始化证书实体
 *
 * @param msg: 证书实体
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_init(gquic_tls_cert_t *const msg);

/**
 * 析构证书实体
 *
 * @param msg: 证书实体
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_dtor(gquic_tls_cert_t *const msg);

/**
 * 证书实体长度
 *
 * @param msg: 证书实体
 *
 * @return: 证书实体长度
 */
ssize_t gquic_tls_cert_size(const gquic_tls_cert_t *const msg);

/**
 * 证书实体序列化
 *
 * @param msg: 证书实体
 * @param writer: writer
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_serialize(const gquic_tls_cert_t *const msg, gquic_writer_str_t *const writer);

/**
 * 反序列化证书实体
 *
 * @param msg: 证书实体
 * @param reader: reader
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_deserialize(gquic_tls_cert_t *const msg, gquic_reader_str_t *const reader);

#endif

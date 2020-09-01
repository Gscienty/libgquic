/* include/tls/ticket.h TLS票证
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_TICKET_H
#define _LIBGQUIC_TLS_TICKET_H

#include "util/str.h"
#include "tls/cert.h"
#include "exception.h"
#include <sys/types.h>

/**
 * TLS会话状态
 */
typedef struct gquic_tls_sess_state_s gquic_tls_sess_state_t;
struct gquic_tls_sess_state_s {
    u_int16_t cipher_suite;
    u_int64_t create_at;
    gquic_str_t resumption_sec;
    gquic_tls_cert_t cert;
};

/**
 * 初始化TLS会话状态
 *
 * @param state: TLS会话状态
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_sess_state_init(gquic_tls_sess_state_t *const state);

/**
 * 析构TLS会话状态
 *
 * @param state: TLS会话状态
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_sess_state_dtor(gquic_tls_sess_state_t *const state);

/**
 * TLS会话状态长度
 *
 * @param state: TLS会话状态
 *
 * @return: exception
 */
ssize_t gquic_tls_sess_state_size(const gquic_tls_sess_state_t *const state);

/**
 * 序列化TLS会话状态
 *
 * @param state: TLS会话状态
 * @param writer: writer
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_sess_state_serialize(const gquic_tls_sess_state_t *const state, gquic_writer_str_t *const writer);

/**
 * 反序列化TLS会话状态
 *
 * @param state: TLS会话状态
 * @param reader: reader
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_sess_state_deserialize(gquic_tls_sess_state_t *const state, gquic_reader_str_t *const reader);

#endif

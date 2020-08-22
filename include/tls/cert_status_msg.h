/* include/tls/cert_status_msg.h TLS CERT_STATUS record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CERT_STATUS_MSG_H
#define _LIBGQUIC_TLS_CERT_STATUS_MSG_H

#include "util/str.h"
#include "exception.h"

/**
 * CERT_STATUS record
 */
typedef struct gquic_tls_cert_status_msg_s gquic_tls_cert_status_msg_t;
struct gquic_tls_cert_status_msg_s {
    gquic_str_t res;
};

/**
 * 申请一个CERT_STATUS record
 *
 * @return result: CERT_STATUS record
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_status_msg_alloc(gquic_tls_cert_status_msg_t **const result);
#endif

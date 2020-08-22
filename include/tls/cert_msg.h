/* include/tls/cert_msg.h TLS CERT record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CERT_MSG_H
#define _LIBGQUIC_TLS_CERT_MSG_H

#include "tls/cert.h"
#include "exception.h"

/**
 * CERT record
 */
typedef struct gquic_tls_cert_msg_s gquic_tls_cert_msg_t;
struct gquic_tls_cert_msg_s {
    gquic_tls_cert_t cert;
};

/**
 * 申请一个CERT record
 *
 * @return result: CERT record
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_msg_alloc(gquic_tls_cert_msg_t **const result);
#endif

/* include/tls/cert_verify_msg.h TLS CERT_VERIFY record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CERT_VERIFY_MSG_H
#define _LIBGQUIC_TLS_CERT_VERIFY_MSG_H

#include "util/str.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>

/**
 * CERT_VERIFY record
 */
typedef struct gquic_tls_cert_verify_msg_s gquic_tls_cert_verify_msg_t;
struct gquic_tls_cert_verify_msg_s {
    bool has_sign_algo;
    u_int16_t sign_algo;
    gquic_str_t sign;
};

/**
 * 申请一个CERT_VERIFY record
 *
 * @return result: CERT_VERIFY record
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_verify_msg_alloc(gquic_tls_cert_verify_msg_t **const result);
#endif

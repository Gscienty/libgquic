/* include/tls/cert_req_msg.h TLS CERT_REQ record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CERT_REQ_MSG_H
#define _LIBGQUIC_TLS_CERT_REQ_MSG_H

#include "util/list.h"
#include "exception.h"
#include <sys/types.h>
#include <stdbool.h>

/**
 * CERT_REQ record
 */
typedef struct gquic_tls_cert_req_msg_s gquic_tls_cert_req_msg_t;
struct gquic_tls_cert_req_msg_s {
    bool ocsp_stapling;
    bool scts;
    gquic_list_t supported_sign_algo;
    gquic_list_t supported_sign_algo_cert;
    gquic_list_t cert_auths;
};

/**
 * 申请一个CERT_REQ record
 *
 * @return result: CERT_REQ record
 * @return: exception
 */
gquic_exception_t gquic_tls_cert_req_msg_alloc(gquic_tls_cert_req_msg_t **const result);
#endif

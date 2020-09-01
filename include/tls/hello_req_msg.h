/* include/tls/hello_req_msg.h TLS HELLO_REQ record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_HELLO_REQ_MSG_H
#define _LIBGQUIC_TLS_HELLO_REQ_MSG_H

#include <sys/types.h>
#include "exception.h"

/**
 * HELLO_REQ record
 */
typedef struct gquic_tls_hello_req_msg_s gquic_tls_hello_req_msg_t;
struct gquic_tls_hello_req_msg_s { };

/**
 * 申请一个HELLO_REQ record
 *
 * @return result: HELLO_REQ record
 * @return: exception
 */
gquic_exception_t gquic_tls_hello_req_msg_alloc(gquic_tls_hello_req_msg_t **const result);
#endif

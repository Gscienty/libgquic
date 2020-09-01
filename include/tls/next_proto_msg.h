/* include/tls/next_proto_msg.h TLS NEXT_PROTO record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_NEXT_PROTO_MSG_H
#define _LIBGQUIC_TLS_NEXT_PROTO_MSG_H

#include "util/str.h"
#include "exception.h"

/**
 * NEXT_PROTO record
 */
typedef struct gquic_tls_next_proto_msg_s gquic_tls_next_proto_msg_t;
struct gquic_tls_next_proto_msg_s {
    gquic_str_t verify;
};

/**
 * 申请一个NEXT_PROTO record
 *
 * @return result: NEXT_PROTO record
 * @return: exception
 */
gquic_exception_t gquic_tls_next_proto_msg_alloc(gquic_tls_next_proto_msg_t **const result);
#endif

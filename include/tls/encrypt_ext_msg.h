/* include/tls/encrypt_ext_msg.h TLS ENCRYPT_EXT record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H
#define _LIBGQUIC_TLS_ENCRYPT_EXT_MSG_H

#include "util/str.h"
#include "util/list.h"
#include "exception.h"

/**
 * ENCRYPT_EXT record
 */
typedef struct gquic_tls_encrypt_ext_msg_s gquic_tls_encrypt_ext_msg_t;
struct gquic_tls_encrypt_ext_msg_s {
    gquic_str_t alpn_proto;
    gquic_list_t addition_exts;
};

/**
 * 申请一个ENCRYPT_EXT record
 * 
 * @return result: ENCRYPT_EXT record
 * @return: exception
 */
gquic_exception_t gquic_tls_encrypt_ext_msg_alloc(gquic_tls_encrypt_ext_msg_t **const result);
#endif

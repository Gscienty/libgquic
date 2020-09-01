/* include/tls/server_key_exchange_msg.h TLS SERVER_KEY_EXCHANGE record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_SERVER_KEY_EXCHANGE_MSG_H
#define _LIBGQUIC_TLS_SERVER_KEY_EXCHANGE_MSG_H

#include "util/str.h"
#include "exception.h"

/**
 * SERVER_KEY_EXCHANGE record
 */
typedef struct gquic_tls_server_key_exchange_msg_s gquic_tls_server_key_exchange_msg_t;
struct gquic_tls_server_key_exchange_msg_s {
    gquic_str_t key;
};

/**
 * 申请一个SERVER_KEY_EXCHANGE record
 *
 * @return result: SERVER_KEY_EXCHANGE record
 * @return: exception
 */
gquic_exception_t gquic_tls_server_key_exchange_msg_alloc(gquic_tls_server_key_exchange_msg_t **const result);
#endif

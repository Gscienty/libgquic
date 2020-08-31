/* include/tls/client_key_exchange_msg.h TLS CLIENT_KEY_EXCHANGE record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_CLIENT_KEY_EXCHANGE_MSG_H
#define _LIBGQUIC_TLS_CLIENT_KEY_EXCHANGE_MSG_H

#include "util/str.h"
#include "exception.h"

/**
 * CLIENT_KEY_EXCHANGE record
 */
typedef struct gquic_tls_client_key_exchange_msg_s gquic_tls_client_key_exchange_msg_t;
struct gquic_tls_client_key_exchange_msg_s {
    gquic_str_t cipher;
};

/**
 * 申请一个CLIENT_KEY_EXCHANGE record
 *
 * @return result: CLIENT_KEY_EXCHANGE record
 * @return: exception
 */
gquic_exception_t gquic_tls_client_key_exchange_msg_alloc(gquic_tls_client_key_exchange_msg_t **const result);
#endif

/* include/tls/key_update_msg.h TLS KEY_UPDATE record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_KEY_UPDATE_MSG_H
#define _LIBGQUIC_TLS_KEY_UPDATE_MSG_H

#include "exception.h"
#include <sys/types.h>

/**
 * KEY_UPDATE record
 */
typedef struct gquic_tls_key_update_msg_s gquic_tls_key_update_msg_t;
struct gquic_tls_key_update_msg_s {
    int req;
};

/**
 * 申请一个KEY_UPDATE record
 *
 * @return result: KEY_UPDATE record
 * @return: exception
 */
gquic_exception_t gquic_tls_key_update_msg_alloc(gquic_tls_key_update_msg_t **const result);
#endif

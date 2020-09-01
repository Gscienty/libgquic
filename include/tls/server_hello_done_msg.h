/* include/tls/server_hello_done_msg.h TLS SERVER_HELLO_DONE record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_SERVER_HELLO_DONE_MSG_H
#define _LIBGQUIC_TLS_SERVER_HELLO_DONE_MSG_H

#include "exception.h"
#include <sys/types.h>

/**
 * SERVER_HELLO_DONE record
 */
typedef struct gquic_tls_server_hello_done_msg_s gquic_tls_server_hello_done_msg_t;
struct gquic_tls_server_hello_done_msg_s { };

/**
 * 申请一个SERVER_HELLO_DONE record
 *
 * @return result: SERVER_HELLO_DONE record
 * @return: exception
 */
gquic_exception_t gquic_tls_server_hello_done_msg_alloc(gquic_tls_server_hello_done_msg_t **const result);
#endif

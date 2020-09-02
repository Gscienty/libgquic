/* include/tls/finished_msg.h TLS FINISHED record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_FINISHED_MSG_H
#define _LIBGQUIC_TLS_FINISHED_MSG_H

#include "util/str.h"
#include "exception.h"

/**
 * FINISHED record
 */
typedef struct gquic_tls_finished_msg_s gquic_tls_finished_msg_t;
struct gquic_tls_finished_msg_s {
    gquic_str_t verify;
};

/**
 * 申请一个FINISHED record
 *
 * @return result: FINSHED record
 * @return: exception
 */
gquic_exception_t gquic_tls_finished_msg_alloc(gquic_tls_finished_msg_t **const result);
#endif

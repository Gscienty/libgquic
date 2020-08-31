/* include/tls/conn.h TLS END_OF_EARLY_DATA record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H
#define _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H

#include "exception.h"
#include <sys/types.h>

/**
 * END_OF_EARLY_DATA record
 */
typedef struct gquic_tls_end_of_early_data_msg_s gquic_tls_end_of_early_data_msg_t;
struct gquic_tls_end_of_early_data_msg_s { };

/**
 * 申请一个END_OF_EARLY_DATA record
 *
 * @return result: END_OF_EARLY_DATA record
 * @return: exception
 */
gquic_exception_t gquic_tls_end_of_early_data_msg_alloc(gquic_tls_end_of_early_data_msg_t **const result);
#endif

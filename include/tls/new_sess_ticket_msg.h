/* include/tls/new_sess_ticket_msg.h TLS NEW_SESS_TICKET record
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_NEW_SESS_TICKET_MSG_H
#define _LIBGQUIC_TLS_NEW_SESS_TICKET_MSG_H

#include "util/str.h"
#include "exception.h"
#include <sys/types.h>

/**
 * NEW_SESS_TICKET record
 */
typedef struct gquic_tls_new_sess_ticket_msg_s gquic_tls_new_sess_ticket_msg_t;
struct gquic_tls_new_sess_ticket_msg_s {
    u_int32_t lifetime;
    u_int32_t age_add;
    gquic_str_t nonce;
    gquic_str_t label;
    u_int32_t max_early_data;
};


/**
 * 申请一个NEW_SESSION_TICKET record
 *
 * @return result: NET_SESSION_TICKET record
 * @return: exception
 */
gquic_exception_t gquic_tls_new_sess_ticket_msg_alloc(gquic_tls_new_sess_ticket_msg_t **const result);
#endif

#ifndef _LIBGQUIC_TLS_NEW_SESS_TICKET_13_MSG_H
#define _LIBGQUIC_TLS_NEW_SESS_TICKET_13_MSG_H

#include "util/str.h"
#include <sys/types.h>

typedef struct gquic_tls_new_sess_ticket_13_msg_s gquic_tls_new_sess_ticket_13_msg_t;
struct gquic_tls_new_sess_ticket_13_msg_s {
    u_int32_t lifetime;
    u_int32_t age_add;
    gquic_str_t nonce;
    gquic_str_t label;
    u_int32_t max_early_data;
};

gquic_tls_new_sess_ticket_13_msg_t *gquic_tls_new_sess_ticket_13_msg_alloc();
#endif

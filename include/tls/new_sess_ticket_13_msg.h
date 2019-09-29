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

int gquic_tls_new_sess_ticket_13_msg_init(gquic_tls_new_sess_ticket_13_msg_t *msg);
int gquic_tls_new_sess_ticket_13_msg_reset(gquic_tls_new_sess_ticket_13_msg_t *msg);
ssize_t gquic_tls_new_sess_ticket_13_msg_size(const gquic_tls_new_sess_ticket_13_msg_t *msg);
ssize_t gquic_tls_new_sess_ticket_13_msg_serialize(const gquic_tls_new_sess_ticket_13_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_new_sess_ticket_13_msg_deserialize(gquic_tls_new_sess_ticket_13_msg_t *msg, const void *buf, const size_t size);

#endif

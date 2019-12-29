#ifndef _LIBGQUIC_TLS_SERVER_KEY_EXCHANGE_MSG_H
#define _LIBGQUIC_TLS_SERVER_KEY_EXCHANGE_MSG_H

#include "util/str.h"

typedef struct gquic_tls_server_key_exchange_msg_s gquic_tls_server_key_exchange_msg_t;
struct gquic_tls_server_key_exchange_msg_s {
    gquic_str_t key;
};

gquic_tls_server_key_exchange_msg_t *gquic_tls_server_key_exchange_msg_alloc();
#endif

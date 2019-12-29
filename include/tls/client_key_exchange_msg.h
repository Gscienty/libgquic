#ifndef _LIBGQUIC_TLS_CLIENT_KEY_EXCHANGE_MSG_H
#define _LIBGQUIC_TLS_CLIENT_KEY_EXCHANGE_MSG_H

#include "util/str.h"

typedef struct gquic_tls_client_key_exchange_msg_s gquic_tls_client_key_exchange_msg_t;
struct gquic_tls_client_key_exchange_msg_s {
    gquic_str_t cipher;
};

gquic_tls_client_key_exchange_msg_t *gquic_tls_client_key_exchange_msg_alloc();
#endif

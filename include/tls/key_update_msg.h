#ifndef _LIBGQUIC_TLS_KEY_UPDATE_MSG_H
#define _LIBGQUIC_TLS_KEY_UPDATE_MSG_H

#include <sys/types.h>

typedef struct gquic_tls_key_update_msg_s gquic_tls_key_update_msg_t;
struct gquic_tls_key_update_msg_s {
    int req;
};

gquic_tls_key_update_msg_t *gquic_tls_key_update_msg_alloc();
#endif

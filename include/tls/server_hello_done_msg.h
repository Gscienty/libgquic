#ifndef _LIBGQUIC_TLS_SERVER_HELLO_DONE_MSG_H
#define _LIBGQUIC_TLS_SERVER_HELLO_DONE_MSG_H

#include <sys/types.h>

typedef struct gquic_tls_server_hello_done_msg_s gquic_tls_server_hello_done_msg_t;
struct gquic_tls_server_hello_done_msg_s { };

int gquic_tls_server_hello_done_msg_alloc(gquic_tls_server_hello_done_msg_t **const result);
#endif

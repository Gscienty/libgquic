#ifndef _LIBGQUIC_TLS_HELLO_REQ_MSG_H
#define _LIBGQUIC_TLS_HELLO_REQ_MSG_H

#include <sys/types.h>

typedef struct gquic_tls_hello_req_msg_s gquic_tls_hello_req_msg_t;
struct gquic_tls_hello_req_msg_s { };

gquic_tls_hello_req_msg_t *gquic_tls_hello_req_msg_alloc();
#endif

#ifndef _LIBGQUIC_TLS_KEY_AGREEMENT_H
#define _LIBGQUIC_TLS_KEY_AGREEMENT_H

#include "tls/client_hello_msg.h"
#include "tls/server_hello_msg.h"
#include "tls/server_key_exchange_msg.h"
#include "tls/client_key_exchange_msg.h"
#include "tls/config.h"
#include "util/str.h"

typedef struct gquic_tls_key_agreement_s gquic_tls_key_agreement_t;
struct gquic_tls_key_agreement_s {
    u_int8_t type;
    void *self;
    int (*generate_ser_key_exchange)(gquic_tls_server_key_exchange_msg_t *const,
                                     void *const,
                                     const gquic_tls_config_t *const,
                                     const gquic_str_t *const,
                                     const gquic_tls_client_hello_msg_t *const,
                                     const gquic_tls_server_hello_msg_t *const);
    int (*process_cli_key_exchange)(gquic_str_t *const,
                                    void *const,
                                    const gquic_tls_config_t *const,
                                    const gquic_str_t *const,
                                    const gquic_tls_client_key_exchange_msg_t *const,
                                    u_int16_t);

    int (*generate_cli_key_exchange)(gquic_str_t *const,
                                     gquic_tls_client_key_exchange_msg_t *const,
                                     void *const,
                                     const gquic_tls_config_t *const,
                                     const gquic_tls_client_hello_msg_t *const,
                                     const gquic_str_t *const);
    int (*process_ser_key_exchange)(void *const,
                                    const gquic_tls_config_t *const,
                                    const gquic_tls_client_hello_msg_t *const,
                                    const gquic_tls_server_hello_msg_t *const,
                                    const gquic_str_t *const,
                                    const gquic_tls_server_key_exchange_msg_t *const);
};

int gquic_tls_key_agreement_release(gquic_tls_key_agreement_t *const key_agreement);
int gquic_tls_key_agreement_rsa_init(gquic_tls_key_agreement_t *const key_agreement);
int gquic_tls_key_agreement_ecdhe_init(gquic_tls_key_agreement_t *const key_agreement);

#endif

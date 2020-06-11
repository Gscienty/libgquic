#ifndef _LIBGQUIC_HANDSHAKE_EXTENSION_HANDLER_H
#define _LIBGQUIC_HANDSHAKE_EXTENSION_HANDLER_H

#include "util/str.h"
#include "handshake/transport_parameters.h"
#include "tls/config.h"
#include "liteco.h"

typedef struct gquic_handshake_extension_handler_s gquic_handshake_extension_handler_t;
struct gquic_handshake_extension_handler_s {
    liteco_channel_t *param_chain;
    gquic_str_t params;
    int is_client;
};

int gquic_handshake_extension_handler_init(gquic_handshake_extension_handler_t *const handler);
int gquic_handshake_extension_handler_ctor(gquic_handshake_extension_handler_t *const handler,
                                           liteco_channel_t *const param_chain,
                                           const gquic_transport_parameters_t *const params,
                                           const int is_client);
int gquic_handshake_extension_handler_dtor(gquic_handshake_extension_handler_t *const handler);
int gquic_handshake_extension_handler_get_extensions(gquic_list_t *const extensions,
                                                     gquic_handshake_extension_handler_t *const handler,
                                                     const u_int8_t msg_type);
int gquic_handshake_extension_handler_recv_extensions(gquic_handshake_extension_handler_t *const handler,
                                                      const u_int8_t msg_type,
                                                      const gquic_list_t *const extensions);
int gquic_handshake_extension_handler_set_config_extension(gquic_tls_config_t *const cfg,
                                                           gquic_handshake_extension_handler_t *const handler);

#endif

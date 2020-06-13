#ifndef _LIBGQUIC_CLOSED_SESSION_H
#define _LIBGQUIC_CLOSED_SESSION_H

#include "packet/handler.h"
#include "net/conn.h"

int gquic_closed_remote_session_client_alloc(gquic_packet_handler_t **const handler_storage);
int gquic_closed_remote_session_server_alloc(gquic_packet_handler_t **const handler_storage);

int gquic_closed_local_session_alloc(gquic_packet_handler_t **const handler_storage,
                                     gquic_net_conn_t *const conn, gquic_str_t *const conn_close_packet, const int is_client);

#endif

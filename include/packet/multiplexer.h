#ifndef _LIBGQUIC_PACKET_MULTIPLEXER_H
#define _LIBGQUIC_PACKET_MULTIPLEXER_H

#include "util/str.h"
#include "packet/packet_handler_map.h"

int gquic_multiplexer_add_conn(gquic_packet_handler_map_t **const handler_storage,
                               const int conn_fd, const int conn_id_len, const gquic_str_t *const stateless_reset_token);
int gquic_multiplexer_remove_conn(const int conn_fd);

#endif

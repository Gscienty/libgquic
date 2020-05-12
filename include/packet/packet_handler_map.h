#ifndef _LIBGQUIC_PACKET_HANDLER_MAP_H
#define _LIBGQUIC_PACKET_HANDLER_MAP_H

#include "util/rbtree.h"
#include "packet/received_packet.h"
#include "packet/handler.h"
#include <semaphore.h>
#include <openssl/hmac.h>

typedef struct gquic_packet_unknow_packet_handler_s gquic_packet_unknow_packet_handler_t;
struct gquic_packet_unknow_packet_handler_s {
    struct {
        void *self;
        int (*cb) (void *const, gquic_received_packet_t *const);
    } handle_packet;
    struct {
        void *self;
        int (*cb) (void *const, const int);
    } set_close_err;
};
int gquic_packet_unknow_packet_handler_init(gquic_packet_unknow_packet_handler_t *const handler);

#define GQUIC_PACKET_UNKNOW_PACKET_HANDLER_HANDLE_PACKET(handler, packet) \
    ((handler)->handle_packet.cb((handler)->handle_packet.self, (packet)))
#define GQUIC_PACKET_UNKNOW_PACKET_HANDLER_SET_CLOSE_ERR(handler, err) \
    ((handler)->set_close_err.cb((handler)->set_close_err.self, (err)))

typedef struct gquic_packet_handler_map_s gquic_packet_handler_map_t;
struct gquic_packet_handler_map_s {
    sem_t mtx;

    int conn_fd;
    int conn_id_len;

    gquic_rbtree_t *handlers; /* gquic_str_t: gquic_packet_handler_t * */
    gquic_rbtree_t *reset_tokens; /* gquic_str_t: gquic_packet_handler_t * */
    gquic_packet_unknow_packet_handler_t *server;

    sem_t listening;
    int closed;

    u_int64_t delete_retired_session_after;

    int stateless_reset_enabled;
    gquic_str_t stateless_reset_key;
};
int gquic_packet_handler_map_init(gquic_packet_handler_map_t *const handler);
int gquic_packet_handler_map_ctor(gquic_packet_handler_map_t *const handler,
                                  const int conn_fd,
                                  const int conn_id_len,
                                  const gquic_str_t *const stateless_reset_token);
int gquic_packet_handler_map_dtor(gquic_packet_handler_map_t *const handler);
int gquic_packet_handler_map_add(gquic_str_t *const token,
                                 gquic_packet_handler_map_t *const handler,
                                 const gquic_str_t *const conn_id,
                                 gquic_packet_handler_t *const ph);
int gquic_packet_handler_map_handle_packet(gquic_packet_handler_map_t *const handle_map, gquic_received_packet_t *const rp);
int gquic_packet_handler_map_add_if_not_taken(gquic_packet_handler_map_t *handler,
                                              const gquic_str_t *const conn_id,
                                              gquic_packet_handler_t *const ph);
int gquic_packet_handler_map_remove(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id);
int gquic_packet_handler_map_retire(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id);
int gquic_packet_handler_map_replace_with_closed(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph);
int gquic_packet_handler_map_add_reset_token(gquic_packet_handler_map_t *const handler,
                                             const gquic_str_t *const token,
                                             gquic_packet_handler_t *const ph);
int gquic_packet_handler_map_remove_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token);
int gquic_packet_handler_map_retire_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token);
int gquic_packet_handler_map_set_server(gquic_packet_handler_map_t *const handler, gquic_packet_unknow_packet_handler_t *const uph);
int gquic_packet_handler_map_close_server(gquic_coroutine_t *const co, gquic_packet_handler_map_t *const handler);
int gquic_packet_handler_map_close(gquic_packet_handler_map_t *const handler);
int gquic_packet_handler_map_get_stateless_reset_token(gquic_str_t *const token,
                                                       gquic_packet_handler_map_t *const handler,
                                                       const gquic_str_t *const conn_id);

#endif

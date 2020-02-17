#ifndef _LIBGQUIC_PACKET_CONN_ID_MANAGER_H
#define _LIBGQUIC_PACKET_CONN_ID_MANAGER_H

#include "util/list.h"
#include "util/str.h"
#include "frame/new_connection_id.h"
#include <sys/types.h>

typedef struct gquic_new_conn_id_s gquic_new_conn_id_t;
struct gquic_new_conn_id_s {
    u_int64_t seq;
    gquic_str_t conn_id;
    u_int8_t token[16];
};

typedef struct gquic_conn_id_manager_s gquic_conn_id_manager_t;
struct gquic_conn_id_manager_s {
    int queue_len;
    gquic_list_t queue;

    u_int64_t active_seq;
    u_int64_t highest_retired;
    gquic_str_t active_conn_id;
    gquic_str_t active_stateless_reset_token;

    u_int64_t packets_since_last_change;
    u_int64_t packets_per_conn_id;

    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } add_stateless_reset_token;
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } remove_stateless_reset_token;
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } retire_stateless_reset_token;
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_ctrl_frame;
};

#define GQUIC_CONN_ID_MANAGER_ADD_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->add_stateless_reset_token.cb((manager)->add_stateless_reset_token.self, (token)))
#define GQUIC_CONN_ID_MANAGER_REMOVE_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->remove_stateless_reset_token.cb((manager)->remove_stateless_reset_token.self, (token)))
#define GQUIC_CONN_ID_MANAGER_RETIRE_STATELESS_RESET_TOKEN(manager, token) \
    ((manager)->retire_stateless_reset_token.cb((manager)->retire_stateless_reset_token.self, (token)))
#define GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, frame) \
    ((manager)->queue_ctrl_frame.cb((manager)->queue_ctrl_frame.self, (frame)))

int guqic_conn_id_manager_init(gquic_conn_id_manager_t *const manager);
int gquic_conn_id_manager_ctor(gquic_conn_id_manager_t *const manager,
                               const gquic_str_t *const initial_dst_conn_id,
                               void *const add_self,
                               int (*add_cb)(void *const, const gquic_str_t *const),
                               void *const remove_self,
                               int (*remove_cb) (void *const, const gquic_str_t *const),
                               void *const retire_self,
                               int (*retire_cb) (void *const, const gquic_str_t *const),
                               void *const queue_ctrl_frame_self,
                               int (*queue_ctrl_frame_cb) (void *const, void *const));
int gquic_conn_id_manager_add(gquic_conn_id_manager_t *const manager, gquic_frame_new_connection_id_t *const frame);
int gquic_conn_id_manager_close(gquic_conn_id_manager_t *const manager);
int gquic_conn_id_manager_change_initial_conn_id(gquic_conn_id_manager_t *const manager, const gquic_str_t *const conn_id);
int gquic_conn_id_manager_set_stateless_reset_token(gquic_conn_id_manager_t *const manager, gquic_str_t *const token);
int gquic_conn_id_manager_get_conn_id(gquic_str_t *const conn_id, gquic_conn_id_manager_t *const manager);

#endif

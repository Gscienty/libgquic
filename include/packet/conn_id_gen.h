#ifndef _LIBGQUIC_PACKET_CONN_ID_GEN_H
#define _LIBGQUIC_PACKET_CONN_ID_GEN_H

#include "packet/handler.h"
#include "util/rbtree.h"
#include "util/str.h"

typedef struct gquic_conn_id_gen_s gquic_conn_id_gen_t;
struct gquic_conn_id_gen_s {
    int conn_id_len;
    u_int64_t highest_seq;

    gquic_rbtree_t *active_src_conn_ids; /* u_int64_t : gquic_str_t */
    gquic_str_t initial_cli_dst_conn_id;

    struct {
        void *self;
        int (*cb) (gquic_str_t *const, void *const, const gquic_str_t *const);
    } add_conn_id;
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } remove_conn_id;
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const);
    } retire_conn_id;
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const, gquic_packet_handler_t *const);
    } replace_with_closed;
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_ctrl_frame;
};

#define GQUIC_CONN_ID_GEN_ADD_CONN_ID(token, gen, conn_id) \
    ((gen)->add_conn_id.cb((token), (gen)->add_conn_id.self, (conn_id)))
#define GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, conn_id) \
    ((gen)->remove_conn_id.cb((gen)->remove_conn_id.self, (conn_id)))
#define GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, conn_id) \
    ((gen)->retire_conn_id.cb((gen)->retire_conn_id.self, (conn_id)))
#define GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, conn_id, packet_handler) \
    ((gen)->replace_with_closed.cb((gen)->replace_with_closed.self, (conn_id), (packet_handler)))
#define GQUIC_CONN_ID_GEN_QUEUE_CTRL_FRAME(gen, frame) \
    ((gen)->queue_ctrl_frame.cb((gen)->queue_ctrl_frame.self, (frame)))

int gquic_conn_id_gen_init(gquic_conn_id_gen_t *const gen);
int gquic_conn_id_gen_ctor(gquic_conn_id_gen_t *const gen,
                           const gquic_str_t *const initial_conn_id,
                           const gquic_str_t *const initial_cli_dst_conn_id,
                           void *const add_conn_id_self,
                           int (*add_conn_id_cb) (gquic_str_t *const, void *const, const gquic_str_t *const),
                           void *const remove_conn_id_self,
                           int (*remove_conn_id_cb) (void *const, const gquic_str_t *const),
                           void *const retrie_conn_id_self,
                           int (*retrie_conn_id_cb) (void *const, const gquic_str_t *const),
                           void *const replace_with_closed_self,
                           int (*replace_with_closed_cb) (void *const, const gquic_str_t *const, gquic_packet_handler_t *const),
                           void *const queue_ctrl_frame_self,
                           int (*queue_ctrl_frame_cb) (void *const, void *const));
int gquic_conn_id_gen_set_max_active_conn_ids(gquic_conn_id_gen_t *const gen, const u_int64_t limit);
int gquic_conn_id_gen_retire(gquic_conn_id_gen_t *const gen, const u_int64_t seq);
int gquic_conn_id_gen_set_handshake_complete(gquic_conn_id_gen_t *const gen);
int gquic_conn_id_gen_remove_all(gquic_conn_id_gen_t *const gen);
int gquic_conn_id_gen_replace_with_closed(gquic_conn_id_gen_t *const gen,
                                          int (*closed_handler_alloc) (gquic_packet_handler_t **const handler, void *const self),
                                          void *const self);

#endif

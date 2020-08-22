/* src/packet/conn_id_gen.c connection id 生成模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/conn_id_gen.h"
#include "frame/new_connection_id.h"
#include "frame/meta.h"
#include "exception.h"
#include <openssl/rand.h>
#include <string.h>

/**
 * 发布一个新的connection id
 *
 * @param gen: 生成模块
 *
 * @return: exception
 */
static gquic_exception_t gquic_conn_id_gen_issue_new_conn_id(gquic_conn_id_gen_t *const gen);

gquic_exception_t gquic_conn_id_gen_init(gquic_conn_id_gen_t *const gen) {
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gen->conn_id_len = 0;
    gen->highest_seq = 0;

    gquic_rbtree_root_init(&gen->active_src_conn_ids);
    gquic_str_init(&gen->initial_cli_dst_conn_id);

    gen->add_conn_id.cb = NULL;
    gen->add_conn_id.self = NULL;
    gen->remove_conn_id.cb = NULL;
    gen->remove_conn_id.self = NULL;
    gen->retire_conn_id.cb = NULL;
    gen->retire_conn_id.self = NULL;
    gen->replace_with_closed.cb = NULL;
    gen->replace_with_closed.self = NULL;
    gen->queue_ctrl_frame.cb = NULL;
    gen->queue_ctrl_frame.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_gen_ctor(gquic_conn_id_gen_t *const gen,
                                         const gquic_str_t *const initial_conn_id,
                                         const gquic_str_t *const initial_cli_dst_conn_id,
                                         void *const add_conn_id_self,
                                         gquic_exception_t (*add_conn_id_cb) (gquic_str_t *const, void *const, const gquic_str_t *const),
                                         void *const remove_conn_id_self,
                                         gquic_exception_t (*remove_conn_id_cb) (void *const, const gquic_str_t *const),
                                         void *const retrie_conn_id_self,
                                         gquic_exception_t (*retrie_conn_id_cb) (void *const, const gquic_str_t *const),
                                         void *const replace_with_closed_self,
                                         gquic_exception_t (*replace_with_closed_cb) (void *const, const gquic_str_t *const, gquic_packet_handler_t *const),
                                         void *const queue_ctrl_frame_self,
                                         gquic_exception_t (*queue_ctrl_frame_cb) (void *const, void *const)) {
    gquic_rbtree_t *rbt = NULL;
    if (gen == NULL
        || initial_conn_id == NULL
        || add_conn_id_self == NULL || add_conn_id_cb == NULL
        || remove_conn_id_self == NULL || remove_conn_id_cb == NULL
        || retrie_conn_id_self == NULL || retrie_conn_id_cb == NULL
        || replace_with_closed_self == NULL || replace_with_closed_cb == NULL
        || queue_ctrl_frame_self == NULL || queue_ctrl_frame_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gen->conn_id_len = GQUIC_STR_SIZE(initial_conn_id);
    gen->add_conn_id.cb = add_conn_id_cb;
    gen->add_conn_id.self = add_conn_id_self;
    gen->remove_conn_id.cb = remove_conn_id_cb;
    gen->remove_conn_id.self = remove_conn_id_self;
    gen->retire_conn_id.cb = retrie_conn_id_cb;
    gen->retire_conn_id.self = retrie_conn_id_self;
    gen->replace_with_closed.cb = replace_with_closed_cb;
    gen->replace_with_closed.self = replace_with_closed_self;
    gen->queue_ctrl_frame.cb = queue_ctrl_frame_cb;
    gen->queue_ctrl_frame.self = queue_ctrl_frame_self;

    GQUIC_ASSERT_FAST_RETURN(gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(gquic_str_t)));
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = 0;
    gquic_str_init(GQUIC_RBTREE_VALUE(rbt));
    gquic_str_copy(GQUIC_RBTREE_VALUE(rbt), initial_conn_id);
    gquic_rbtree_insert(&gen->active_src_conn_ids, rbt);
    gquic_str_copy(&gen->initial_cli_dst_conn_id, initial_cli_dst_conn_id);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_gen_set_max_active_conn_ids(gquic_conn_id_gen_t *const gen, const u_int64_t limit) {
    u_int64_t i = 0;
    u_int64_t used_limit = limit;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gen->conn_id_len == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (6 < used_limit) {
        used_limit = 6;
    }
    for (i = 1; i < used_limit; i++) {
        GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_gen_issue_new_conn_id(gen));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_conn_id_gen_issue_new_conn_id(gquic_conn_id_gen_t *const gen) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_str_t conn_id = { 0, NULL };
    gquic_str_t token = { 0, NULL };
    gquic_rbtree_t *rbt = NULL;
    gquic_frame_new_connection_id_t *frame = NULL;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_conn_id_generate(&conn_id, gen->conn_id_len))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(gquic_str_t)))) {
        goto failure;
    }
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = ++gen->highest_seq;
    gquic_str_init(GQUIC_RBTREE_VALUE(rbt));
    *(gquic_str_t *) GQUIC_RBTREE_VALUE(rbt) = conn_id;
    gquic_rbtree_insert(&gen->active_src_conn_ids, rbt);

    if (GQUIC_ASSERT_CAUSE(exception, GQUIC_CONN_ID_GEN_ADD_CONN_ID(&token, gen, &conn_id))) {
        goto failure;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_new_connection_id_alloc(&frame))) {
        goto failure;
    }
    GQUIC_FRAME_INIT(frame);
    memcpy(frame->conn_id, GQUIC_STR_VAL(&conn_id), GQUIC_STR_SIZE(&conn_id));
    frame->len = GQUIC_STR_SIZE(&conn_id);
    frame->seq = *(u_int64_t *) GQUIC_RBTREE_KEY(rbt); 
    memcpy(frame->token, GQUIC_STR_VAL(&token), GQUIC_STR_SIZE(&token));

    GQUIC_CONN_ID_GEN_QUEUE_CTRL_FRAME(gen, frame);

    gquic_str_reset(&conn_id);
    gquic_str_reset(&token);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    gquic_str_reset(&conn_id);
    gquic_str_reset(&token);
    if (rbt != NULL) {
        gquic_str_reset(GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    if (frame != NULL) {
        gquic_frame_release(frame);
    }

    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_conn_id_gen_retire(gquic_conn_id_gen_t *const gen, const u_int64_t seq) {
    gquic_rbtree_t *rbt = NULL;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (seq > gen->highest_seq) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_GREATE_THAN_HIGHEST_SEQ);
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, gen->active_src_conn_ids, &seq, sizeof(u_int64_t)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_remove(&gen->active_src_conn_ids, &rbt);
    gquic_str_reset(GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_release(rbt, NULL);
    if (seq == 0) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_conn_id_gen_issue_new_conn_id(gen));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_gen_set_handshake_complete(gquic_conn_id_gen_t *const gen) {
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, &gen->initial_cli_dst_conn_id);
        gquic_str_reset(&gen->initial_cli_dst_conn_id);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_gen_remove_all(gquic_conn_id_gen_t *const gen) {
    gquic_rbtree_t *payload = NULL;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, &gen->initial_cli_dst_conn_id);
    }

    GQUIC_RBTREE_EACHOR_BEGIN(payload, gen->active_src_conn_ids)
        GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, GQUIC_RBTREE_VALUE(payload));
    GQUIC_RBTREE_EACHOR_END(payload)

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_gen_replace_with_closed(gquic_conn_id_gen_t *const gen,
                                                        gquic_exception_t (*closed_handler_alloc) (gquic_packet_handler_t **const handler, void *const self), void *const self) {
    gquic_rbtree_t *payload = NULL;
    gquic_packet_handler_t *handler = NULL;
    if (gen == NULL || closed_handler_alloc == NULL || self == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        GQUIC_ASSERT_FAST_RETURN(closed_handler_alloc(&handler, self));
        GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, &gen->initial_cli_dst_conn_id, handler);
    }

    GQUIC_RBTREE_EACHOR_BEGIN(payload, gen->active_src_conn_ids)
        GQUIC_ASSERT_FAST_RETURN(closed_handler_alloc(&handler, self));
        GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, GQUIC_RBTREE_VALUE(payload), handler);
    GQUIC_RBTREE_EACHOR_END(payload)

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_generate(gquic_str_t *const conn_id, const size_t len) {
    if (conn_id == NULL || len < 0 || len > 20) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_str_alloc(conn_id, len) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    RAND_bytes(GQUIC_STR_VAL(conn_id), len);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


#include "packet/conn_id_gen.h"
#include "util/conn_id.h"
#include "frame/new_connection_id.h"

static int gquic_conn_id_gen_issue_new_conn_id(gquic_conn_id_gen_t *const);

int gquic_conn_id_gen_init(gquic_conn_id_gen_t *const gen) {
    if (gen == NULL) {
        return -1;
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

    return 0;
}

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
                           int (*queue_ctrl_frame_cb) (void *const, void *const)) {
    gquic_rbtree_t *rbt = NULL;
    if (gen == NULL
        || initial_conn_id == NULL
        || add_conn_id_self == NULL
        || add_conn_id_cb == NULL
        || remove_conn_id_self == NULL
        || remove_conn_id_cb == NULL
        || retrie_conn_id_self == NULL
        || retrie_conn_id_cb == NULL
        || replace_with_closed_self == NULL
        || replace_with_closed_cb == NULL
        || queue_ctrl_frame_self == NULL
        || queue_ctrl_frame_cb == NULL) {
        return -1;
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

    if (gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(gquic_str_t)) != 0) {
        return -1;
    }
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = 0;
    gquic_str_init(GQUIC_RBTREE_VALUE(rbt));
    gquic_str_copy(GQUIC_RBTREE_VALUE(rbt), initial_conn_id);
    gquic_rbtree_insert(&gen->active_src_conn_ids, rbt);
    gquic_str_copy(&gen->initial_cli_dst_conn_id, initial_cli_dst_conn_id);

    return 0;
}

int gquic_conn_id_gen_set_max_active_conn_ids(gquic_conn_id_gen_t *const gen, const u_int64_t limit) {
    u_int64_t i = 0;
    u_int64_t used_limit = limit;
    if (gen == NULL) {
        return -1;
    }
    if (gen->conn_id_len == 0) {
        return 0;
    }
    if (6 < used_limit) {
        used_limit = 6;
    }
    for (i = 1; i < used_limit; i++) {
        if (gquic_conn_id_gen_issue_new_conn_id(gen) != 0) {
            return -2;
        }
    }
    return 0;
}

static int gquic_conn_id_gen_issue_new_conn_id(gquic_conn_id_gen_t *const gen) {
    int ret = 0;
    gquic_str_t conn_id = { 0, NULL };
    gquic_str_t token = { 0, NULL };
    gquic_rbtree_t *rbt = NULL;
    gquic_frame_new_connection_id_t *frame = NULL;
    if (gen == NULL) {
        return -1;
    }
    if (gquic_conn_id_generate(&conn_id, gen->conn_id_len) != 0) {
        ret = -2;
        goto failure;
    }
    if (gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(gquic_str_t)) != 0) {
        ret = -3;
        goto failure;
    }
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = ++gen->highest_seq;
    gquic_str_init(GQUIC_RBTREE_VALUE(rbt));
    *(gquic_str_t *) GQUIC_RBTREE_VALUE(rbt) = conn_id;
    gquic_rbtree_insert(&gen->active_src_conn_ids, rbt);

    if (GQUIC_CONN_ID_GEN_ADD_CONN_ID(&token, gen, &conn_id) != 0) {
        ret = -3;
        goto failure;
    }
    if ((frame = gquic_frame_new_connection_id_alloc()) == NULL) {
        ret = -4;
        goto failure;
    }
    memcpy(frame->conn_id, GQUIC_STR_VAL(&conn_id), GQUIC_STR_SIZE(&conn_id));
    frame->len = GQUIC_STR_SIZE(&conn_id);
    frame->seq = *(u_int64_t *) GQUIC_RBTREE_KEY(rbt); 
    memcpy(frame->token, GQUIC_STR_VAL(&token), GQUIC_STR_SIZE(&token));

    GQUIC_CONN_ID_GEN_QUEUE_CTRL_FRAME(gen, frame);

    gquic_str_reset(&conn_id);
    gquic_str_reset(&token);
    return 0;
failure:
    gquic_str_reset(&conn_id);
    gquic_str_reset(&token);
    if (rbt != NULL) {
        gquic_str_reset(GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }

    return ret;
}

int gquic_conn_id_gen_retire(gquic_conn_id_gen_t *const gen, const u_int64_t seq) {
    gquic_rbtree_t *rbt = NULL;
    if (gen == NULL) {
        return -1;
    }
    if (seq > gen->highest_seq) {
        return -2;
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, gen->active_src_conn_ids, &seq, sizeof(u_int64_t)) != 0) {
        return 0;
    }
    GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_remove(&gen->active_src_conn_ids, &rbt);
    gquic_str_reset(GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_release(rbt, NULL);
    if (seq == 0) {
        return 0;
    }

    return gquic_conn_id_gen_issue_new_conn_id(gen);
}

int gquic_conn_id_gen_set_handshake_complete(gquic_conn_id_gen_t *const gen) {
    if (gen == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        GQUIC_CONN_ID_GEN_RETIRE_CONN_ID(gen, &gen->initial_cli_dst_conn_id);
        gquic_str_reset(&gen->initial_cli_dst_conn_id);
        gquic_str_init(&gen->initial_cli_dst_conn_id);
    }

    return 0;
}

int gquic_conn_id_gen_remove_all(gquic_conn_id_gen_t *const gen) {
    gquic_rbtree_t *payload = NULL;
    if (gen == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, &gen->initial_cli_dst_conn_id);
    }

    GQUIC_RBTREE_EACHOR_BEGIN(payload, gen->active_src_conn_ids)
        GQUIC_CONN_ID_GEN_REMOVE_CONN_ID(gen, GQUIC_RBTREE_VALUE(payload));
    GQUIC_RBTREE_EACHOR_END(payload)
    return 0;
}

int gquic_conn_id_gen_replace_with_closed(gquic_conn_id_gen_t *const gen,
                                          int (*closed_handler_alloc) (gquic_packet_handler_t **const handler, void *const self),
                                          void *const self) {
    gquic_rbtree_t *payload = NULL;
    gquic_packet_handler_t *handler = NULL;
    if (gen == NULL || closed_handler_alloc == NULL || self == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&gen->initial_cli_dst_conn_id) != 0) {
        if (closed_handler_alloc(&handler, self) != 0) {
            return -2;
        }
        GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, &gen->initial_cli_dst_conn_id, handler);
    }

    GQUIC_RBTREE_EACHOR_BEGIN(payload, gen->active_src_conn_ids)
        if (closed_handler_alloc(&handler, self) != 0) {
            return -3;
        }
        GQUIC_CONN_ID_GEN_REPLACE_WITH_CLOSED(gen, GQUIC_RBTREE_VALUE(payload), handler);
    GQUIC_RBTREE_EACHOR_END(payload)
    return 0;
}

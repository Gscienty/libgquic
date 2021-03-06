/* src/packet/conn_id_manager.c connection id 管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/conn_id_manager.h"
#include "frame/retire_connection_id.h"
#include "frame/meta.h"
#include "exception.h"
#include <string.h>
#include <stdbool.h>

static gquic_exception_t gquic_conn_id_update_conn_id(gquic_conn_id_manager_t *const manager);
static bool gquic_conn_id_manager_should_update_conn_id(gquic_conn_id_manager_t *const manager);

gquic_exception_t gquic_conn_id_manager_init(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    manager->queue_len = 0;
    gquic_list_head_init(&manager->queue);

    manager->active_seq = 0;
    manager->highest_retired = 0;
    gquic_str_init(&manager->active_conn_id);
    gquic_str_init(&manager->active_stateless_reset_token);

    manager->packets_count_since_last_change = 0;
    manager->packets_count_limit = 0;

    manager->add_stateless_reset_token.cb = NULL;
    manager->add_stateless_reset_token.self = NULL;
    manager->remove_stateless_reset_token.cb = NULL;
    manager->remove_stateless_reset_token.self = NULL;
    manager->retire_stateless_reset_token.cb = NULL;
    manager->retire_stateless_reset_token.self = NULL;
    manager->queue_ctrl_frame.cb = NULL;
    manager->queue_ctrl_frame.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_ctor(gquic_conn_id_manager_t *const manager,
                                             const gquic_str_t *const initial_dst_conn_id,
                                             void *const add_self, gquic_exception_t (*add_cb)(void *const, const gquic_str_t *const),
                                             void *const remove_self, gquic_exception_t (*remove_cb) (void *const, const gquic_str_t *const),
                                             void *const retire_self, gquic_exception_t (*retire_cb) (void *const, const gquic_str_t *const),
                                             void *const queue_ctrl_frame_self, gquic_exception_t (*queue_ctrl_frame_cb) (void *const, void *const)) {
    if (manager == NULL || initial_dst_conn_id == NULL
        || add_self == NULL || add_cb == NULL
        || remove_self == NULL || remove_cb == NULL
        || retire_self == NULL || retire_cb == NULL
        || queue_ctrl_frame_self == NULL || queue_ctrl_frame_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_copy(&manager->active_conn_id, initial_dst_conn_id);
    manager->add_stateless_reset_token.cb = add_cb;
    manager->add_stateless_reset_token.self = add_self;
    manager->remove_stateless_reset_token.cb = remove_cb;
    manager->remove_stateless_reset_token.self = remove_self;
    manager->retire_stateless_reset_token.cb = retire_cb;
    manager->retire_stateless_reset_token.self = retire_self;
    manager->queue_ctrl_frame.cb = queue_ctrl_frame_cb;
    manager->queue_ctrl_frame.self = queue_ctrl_frame_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_add(gquic_conn_id_manager_t *const manager, gquic_frame_new_connection_id_t *const frame) {
    gquic_new_conn_id_t *new_conn_id = NULL;
    gquic_new_conn_id_t *next_new_conn_id = NULL;
    gquic_frame_retire_connection_id_t *retire_frame = NULL;
    if (manager == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    // 当接收到的新的connection id的序号小于最大丢弃的序号时，该connection id应该通知对端失效
    if (frame->seq < manager->highest_retired) {
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_retire_connection_id_alloc(&retire_frame));
        GQUIC_FRAME_INIT(retire_frame);
        retire_frame->seq = frame->seq;
        GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);

        goto added;
    }

    // 同步失效connection id
    if (frame->prior > manager->highest_retired) {
        for (new_conn_id = GQUIC_LIST_FIRST(&manager->queue);
             new_conn_id != GQUIC_LIST_PAYLOAD(&manager->queue);
             new_conn_id = next_new_conn_id) {
            if (new_conn_id->seq > frame->prior) {
                break;
            }
            next_new_conn_id = gquic_list_next(new_conn_id);
            GQUIC_ASSERT_FAST_RETURN(gquic_frame_retire_connection_id_alloc(&retire_frame));
            GQUIC_FRAME_INIT(retire_frame);
            retire_frame->seq = frame->seq;
            GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);

            gquic_list_remove(new_conn_id);
            manager->queue_len--;
            gquic_str_reset(&new_conn_id->conn_id);
            gquic_list_release(new_conn_id);
        }
        manager->highest_retired = frame->prior;
    }

    // 若接收到的新connection id序号与当前激活的connection id序号一致
    // 则认为没有更新
    if (frame->seq == manager->active_seq) {
        goto added;
    }

    // 依照seq跟已有存放在queue的connection id，维持原有先后顺序的条件下插入新的connection id
    if (gquic_list_head_empty(&manager->queue) || ((gquic_new_conn_id_t *) GQUIC_LIST_LAST(&manager->queue))->seq < frame->seq) {
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &new_conn_id, sizeof(gquic_new_conn_id_t)));
        new_conn_id->seq = frame->seq;
        gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
        gquic_str_copy(&new_conn_id->conn_id, &tmp_conn_id);
        memcpy(new_conn_id->token, frame->token, 16);
        gquic_list_insert_before(&manager->queue, new_conn_id);
        manager->queue_len++;
    }
    else {
        GQUIC_LIST_FOREACH(new_conn_id, &manager->queue) {
            if (new_conn_id->seq == frame->seq) {
                gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
                if (gquic_str_cmp(&new_conn_id->conn_id, &tmp_conn_id) != 0) {
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RECV_CONN_ID_CONFLICT);
                }
                if (memcmp(new_conn_id->token, frame->token, 16) != 0) {
                    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RECV_STATELESS_TOKEN_CONFLICT);
                }
                break;
            }
            if (new_conn_id->seq > frame->seq) {
                next_new_conn_id = new_conn_id;
                GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &new_conn_id, sizeof(gquic_new_conn_id_t)));
                new_conn_id->seq = frame->seq;
                gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
                gquic_str_copy(&new_conn_id->conn_id, &tmp_conn_id);
                memcpy(new_conn_id->token, frame->token, 16);
                gquic_list_insert_before(&GQUIC_LIST_META(next_new_conn_id), new_conn_id);
                new_conn_id = next_new_conn_id;
                break;
            }
        }
    }

    // 若当前激活的connection id失效，则应更新connection id
    if (manager->active_seq < frame->prior) {
        gquic_conn_id_update_conn_id(manager);
    }

added:
    if (manager->queue_len >= 4) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CONN_ID_LIMIT_ERROR);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_conn_id_update_conn_id(gquic_conn_id_manager_t *const manager) {
    gquic_new_conn_id_t *front = NULL;
    gquic_frame_retire_connection_id_t *retire_frame = NULL;
    if (manager == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    // 将当前激活的connection id失效处理
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_retire_connection_id_alloc(&retire_frame));
    GQUIC_FRAME_INIT(retire_frame);
    retire_frame->seq = manager->active_seq;
    GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);

    // 尝试更新最大失效connection id序号
    if (manager->highest_retired < manager->active_seq) {
        manager->highest_retired = manager->active_seq;
    }
    // 使当前激活的connection id对应的token失效
    if (GQUIC_STR_SIZE(&manager->active_stateless_reset_token) != 0) {
        GQUIC_CONN_ID_MANAGER_RETIRE_STATELESS_RESET_TOKEN(manager, &manager->active_stateless_reset_token);
    }
    front = GQUIC_LIST_FIRST(&manager->queue);
    gquic_list_remove(front);
    manager->queue_len--;

    gquic_str_reset(&manager->active_conn_id);
    gquic_str_reset(&manager->active_stateless_reset_token);

    // 使用queue中下一个connection id
    manager->active_seq = front->seq;
    gquic_str_copy(&manager->active_conn_id, &front->conn_id);
    gquic_str_t tmp_token = { 16, front->token };
    gquic_str_copy(&manager->active_stateless_reset_token, &tmp_token);
    manager->packets_count_since_last_change = 0;
    manager->packets_count_limit = 5000;
    GQUIC_CONN_ID_MANAGER_ADD_STATELESS_RESET_TOKEN(manager, &manager->active_stateless_reset_token);

    gquic_str_reset(&front->conn_id);
    gquic_list_release(front);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_close(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_STR_SIZE(&manager->active_stateless_reset_token) != 0) {
        GQUIC_CONN_ID_MANAGER_REMOVE_STATELESS_RESET_TOKEN(manager, &manager->active_stateless_reset_token);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_change_initial_conn_id(gquic_conn_id_manager_t *const manager, const gquic_str_t *const conn_id) {
    if (manager == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (manager->active_seq != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FIRST_CONN_ID_SEQ_NUMBER_UNEXCEPTED);
    }
    gquic_str_reset(&manager->active_conn_id);
    gquic_str_copy(&manager->active_conn_id, conn_id);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_set_stateless_reset_token(gquic_conn_id_manager_t *const manager, gquic_str_t *const token) {
    if (manager == NULL || token == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (manager->active_seq != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_FIRST_CONN_ID_SEQ_NUMBER_UNEXCEPTED);
    }
    gquic_str_reset(&manager->active_stateless_reset_token);
    gquic_str_copy(&manager->active_stateless_reset_token, token);
    GQUIC_CONN_ID_MANAGER_ADD_STATELESS_RESET_TOKEN(manager, token);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_conn_id_manager_get_conn_id(gquic_str_t *const conn_id, gquic_conn_id_manager_t *const manager) {
    if (conn_id == NULL || manager == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_conn_id_manager_should_update_conn_id(manager)) {
        gquic_conn_id_update_conn_id(manager);
    }
    gquic_str_copy(conn_id, &manager->active_conn_id);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static bool gquic_conn_id_manager_should_update_conn_id(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        return false;
    }
    if (!gquic_list_head_empty(&manager->queue) && manager->active_seq == 0) {
        return true;
    }

    return 2 * manager->queue_len >= 4 && manager->packets_count_since_last_change >= manager->packets_count_limit;
}

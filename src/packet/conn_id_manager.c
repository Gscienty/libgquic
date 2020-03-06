#include "packet/conn_id_manager.h"
#include "frame/retire_connection_id.h"
#include <malloc.h>
#include <string.h>

static int gquic_conn_id_update_conn_id(gquic_conn_id_manager_t *const manager);
static int gquic_conn_id_manager_should_update_conn_id(gquic_conn_id_manager_t *const manager);

int gquic_conn_id_manager_init(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        return -1;
    }
    manager->queue_len = 0;
    gquic_list_head_init(&manager->queue);

    manager->active_seq = 0;
    manager->highest_retired = 0;
    gquic_str_init(&manager->active_conn_id);
    gquic_str_init(&manager->active_stateless_reset_token);

    manager->packets_since_last_change = 0;
    manager->packets_per_conn_id = 0;

    manager->add_stateless_reset_token.cb = NULL;
    manager->add_stateless_reset_token.self = NULL;
    manager->remove_stateless_reset_token.cb = NULL;
    manager->remove_stateless_reset_token.self = NULL;
    manager->retire_stateless_reset_token.cb = NULL;
    manager->retire_stateless_reset_token.self = NULL;
    manager->queue_ctrl_frame.cb = NULL;
    manager->queue_ctrl_frame.self = NULL;

    return 0;
}

int gquic_conn_id_manager_ctor(gquic_conn_id_manager_t *const manager,
                               const gquic_str_t *const initial_dst_conn_id,
                               void *const add_self,
                               int (*add_cb)(void *const, const gquic_str_t *const),
                               void *const remove_self,
                               int (*remove_cb) (void *const, const gquic_str_t *const),
                               void *const retire_self,
                               int (*retire_cb) (void *const, const gquic_str_t *const),
                               void *const queue_ctrl_frame_self,
                               int (*queue_ctrl_frame_cb) (void *const, void *const)) {
    if (manager == NULL || initial_dst_conn_id == NULL
        || add_self == NULL || add_cb == NULL
        || remove_self == NULL || remove_cb == NULL
        || retire_self == NULL || retire_cb == NULL
        || queue_ctrl_frame_self == NULL || queue_ctrl_frame_cb == NULL) {
        return -1;
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

    return 0;
}

int gquic_conn_id_manager_add(gquic_conn_id_manager_t *const manager, gquic_frame_new_connection_id_t *const frame) {
    gquic_new_conn_id_t *new_conn_id = NULL;
    gquic_new_conn_id_t *next_new_conn_id = NULL;
    gquic_frame_retire_connection_id_t *retire_frame = NULL;
    if (manager == NULL || frame == NULL) {
        return -1;
    }

    if (frame->seq < manager->highest_retired) {
        if ((retire_frame = gquic_frame_retire_connection_id_alloc()) == NULL) {
            return -2;
        }
        retire_frame->seq = frame->seq;
        GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);
        goto added;
    }
    if (frame->prior > manager->highest_retired) {
        for (new_conn_id = GQUIC_LIST_FIRST(&manager->queue);
             new_conn_id != GQUIC_LIST_PAYLOAD(&manager->queue);
             new_conn_id = next_new_conn_id) {
            if (new_conn_id->seq > frame->prior) {
                break;
            }
            next_new_conn_id = gquic_list_next(new_conn_id);
            if ((retire_frame = gquic_frame_retire_connection_id_alloc()) == NULL) {
                return -2;
            }
            retire_frame->seq = frame->seq;
            GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);
            gquic_list_remove(new_conn_id);
            manager->queue_len--;
            gquic_str_reset(&new_conn_id->conn_id);
            gquic_list_release(new_conn_id);
        }
        manager->highest_retired = frame->prior;
    }

    if (frame->seq == manager->active_seq) {
        goto added;
    }

    if (gquic_list_head_empty(&manager->queue) || ((gquic_new_conn_id_t *) GQUIC_LIST_LAST(&manager->queue))->seq < frame->seq) {
        if ((new_conn_id = gquic_list_alloc(sizeof(gquic_new_conn_id_t))) == NULL) {
            return -3;
        }
        new_conn_id->seq = frame->seq;
        gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
        gquic_str_copy(&new_conn_id->conn_id, &tmp_conn_id);
        memcpy(new_conn_id, frame->token, 16);
        gquic_list_insert_before(&manager->queue, new_conn_id);
        manager->queue_len++;
    }
    else {
        GQUIC_LIST_FOREACH(new_conn_id, &manager->queue) {
            if (new_conn_id->seq == frame->seq) {
                gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
                if (gquic_str_cmp(&new_conn_id->conn_id, &tmp_conn_id) != 0) {
                    return -4;
                }
                if (memcmp(new_conn_id->token, frame->token, 16) != 0) {
                    return -5;
                }
                break;
            }
            if (new_conn_id->seq > frame->seq) {
                next_new_conn_id = new_conn_id;
                if ((new_conn_id = gquic_list_alloc(sizeof(gquic_new_conn_id_t))) == NULL) {
                    return -6;
                }
                new_conn_id->seq = frame->seq;
                gquic_str_t tmp_conn_id = { frame->len, frame->conn_id };
                gquic_str_copy(&new_conn_id->conn_id, &tmp_conn_id);
                memcpy(new_conn_id, frame->token, 16);
                gquic_list_insert_before(&GQUIC_LIST_META(next_new_conn_id), new_conn_id);
                new_conn_id = next_new_conn_id;
                break;
            }
        }
    }

    if (manager->active_seq < frame->prior) {
        gquic_conn_id_update_conn_id(manager);
    }

added:
    if (manager->queue_len >= 4) {
        return -2;
    }
    return 0;
}

static int gquic_conn_id_update_conn_id(gquic_conn_id_manager_t *const manager) {
    gquic_new_conn_id_t *front = NULL;
    gquic_frame_retire_connection_id_t *retire_frame = NULL;
    if (manager == NULL) {
        return -1;
    }
    if ((retire_frame = gquic_frame_retire_connection_id_alloc()) == NULL) {
        return -2;
    }
    retire_frame->seq = manager->active_seq;
    GQUIC_CONN_ID_MANAGER_QUEUE_CTRL_FRAME(manager, retire_frame);
    
    if (manager->highest_retired < manager->active_seq) {
        manager->highest_retired = manager->active_seq;
    }
    if (GQUIC_STR_SIZE(&manager->active_stateless_reset_token) != 0) {
        GQUIC_CONN_ID_MANAGER_RETIRE_STATELESS_RESET_TOKEN(manager, &manager->active_stateless_reset_token);
    }
    front = GQUIC_LIST_FIRST(&manager->queue);
    gquic_list_remove(front);
    manager->queue_len--;

    manager->active_seq = front->seq;
    gquic_str_copy(&manager->active_conn_id, &front->conn_id);
    gquic_str_t tmp_token = { 16, front->token };
    gquic_str_copy(&manager->active_stateless_reset_token, &tmp_token);
    manager->packets_since_last_change = 0;
    manager->packets_per_conn_id = 5000;
    gquic_str_reset(&manager->active_stateless_reset_token);
    gquic_str_init(&manager->active_stateless_reset_token);

    gquic_str_reset(&front->conn_id);
    gquic_list_release(front);
    return 0;
}

int gquic_conn_id_manager_close(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(&manager->active_stateless_reset_token) != 0) {
        GQUIC_CONN_ID_MANAGER_REMOVE_STATELESS_RESET_TOKEN(manager, &manager->active_stateless_reset_token);
    }
    
    return 0;
}

int gquic_conn_id_manager_change_initial_conn_id(gquic_conn_id_manager_t *const manager, const gquic_str_t *const conn_id) {
    if (manager == NULL || conn_id == NULL) {
        return -1;
    }
    if (manager->active_seq != 0) {
        return -2;
    }
    gquic_str_reset(&manager->active_conn_id);
    gquic_str_init(&manager->active_conn_id);
    gquic_str_copy(&manager->active_conn_id, conn_id);

    return 0;
}

int gquic_conn_id_manager_set_stateless_reset_token(gquic_conn_id_manager_t *const manager, gquic_str_t *const token) {
    if (manager == NULL || token == NULL) {
        return -1;
    }
    if (manager->active_seq != 0) {
        return -2;
    }
    gquic_str_reset(&manager->active_stateless_reset_token);
    gquic_str_init(&manager->active_stateless_reset_token);
    gquic_str_copy(&manager->active_stateless_reset_token, token);
    GQUIC_CONN_ID_MANAGER_ADD_STATELESS_RESET_TOKEN(manager, token);

    return 0;
}

int gquic_conn_id_manager_get_conn_id(gquic_str_t *const conn_id, gquic_conn_id_manager_t *const manager) {
    if (conn_id == NULL || manager == NULL) {
        return -1;
    }
    if (gquic_conn_id_manager_should_update_conn_id(manager)) {
        gquic_conn_id_update_conn_id(manager);
    }
    gquic_str_copy(conn_id, &manager->active_conn_id);
    return 0;
}

static int gquic_conn_id_manager_should_update_conn_id(gquic_conn_id_manager_t *const manager) {
    if (manager == NULL) {
        return 0;
    }
    if (!gquic_list_head_empty(&manager->queue) && manager->active_seq == 0) {
        return 1;
    }

    return 2 * manager->queue_len >= 4 && manager->packets_since_last_change >= manager->packets_per_conn_id;
}

#include "streams/inbidi_stream_map.h"
#include "frame/meta.h"
#include "frame/max_streams.h"

static int gquic_inbidi_stream_map_delete_stream_inner(gquic_inbidi_stream_map_t *const, const u_int64_t);

int gquic_inbidi_stream_map_init(gquic_inbidi_stream_map_t *const str_map) {
    if (str_map == NULL) {
        return -1;
    }
    sem_init(&str_map->mtx, 0, 1);
    sem_init(&str_map->new_stream_sem, 0, 0);

    gquic_rbtree_root_init(&str_map->streams_root);
    str_map->streams_count = 0;
    gquic_rbtree_root_init(&str_map->streams_del_root);

    str_map->next_stream_accept = 0;
    str_map->next_stream_open = 0;
    str_map->max_stream = 0;
    str_map->max_stream_count = 0;

    str_map->stream_ctor.cb = NULL;
    str_map->stream_ctor.self = NULL;

    str_map->queue_max_stream_id.cb = NULL;
    str_map->queue_max_stream_id.self = NULL;

    str_map->closed = 0;
    str_map->closed_reason = 0;

    return 0;
}

int gquic_inbidi_stream_map_ctor(gquic_inbidi_stream_map_t *const str_map,
                                 void *const new_stream_self,
                                 int (*new_stream_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                 u_int64_t max_stream_count,
                                 void *const queue_max_stream_id_self,
                                 int (*queue_max_stream_id_cb) (void *const, const void *const)) {
    if (str_map == NULL || new_stream_self == NULL || new_stream_cb == NULL || queue_max_stream_id_self == NULL || queue_max_stream_id_cb == NULL) {
        return -1;
    }
    str_map->max_stream_count = max_stream_count;
    str_map->max_stream = max_stream_count;
    str_map->stream_ctor.self = new_stream_self;
    str_map->stream_ctor.cb = new_stream_cb;
    str_map->queue_max_stream_id.self = queue_max_stream_id_self;
    str_map->queue_max_stream_id.cb = queue_max_stream_id_cb;
    str_map->next_stream_open = 1;
    str_map->next_stream_accept = 1;

    return 0;
}

int gquic_inbidi_stream_map_accept_stream(gquic_stream_t **const str, gquic_inbidi_stream_map_t *const str_map) {
    u_int64_t num = 0;
    const gquic_rbtree_t *rb_str = NULL;
    const gquic_rbtree_t *rb_del_str = NULL;
    int ret = 0;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    sem_wait(&str_map->mtx);

    for ( ;; ) {
        num = str_map->next_stream_accept;
        if (str_map->closed != 0) {
            ret = str_map->closed_reason;
            goto finished;
        }
        if (gquic_rbtree_find(&rb_str, str_map->streams_root, &num, sizeof(u_int64_t)) == 0) {
            break;
        }
        sem_post(&str_map->mtx);
        sem_wait(&str_map->new_stream_sem);
        sem_wait(&str_map->mtx);
    }
    str_map->next_stream_accept++;
    if (gquic_rbtree_find(&rb_del_str, str_map->streams_del_root, &num, sizeof(u_int64_t)) == 0) {
        gquic_rbtree_remove(&str_map->streams_del_root, (gquic_rbtree_t **) &rb_del_str);
        gquic_rbtree_release((gquic_rbtree_t *) rb_del_str, NULL);
        if ((ret = gquic_inbidi_stream_map_delete_stream_inner(str_map, num)) != 0) {
            goto finished;
        }
    }
    *str = GQUIC_RBTREE_VALUE(rb_str);
finished:
    sem_post(&str_map->mtx);
    return ret;
}

int gquic_inbidi_stream_map_get_or_open_stream(gquic_stream_t **const str, gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    u_int64_t new_num = 0;
    gquic_rbtree_t *rb_str = NULL;
    int ret = 0;
    if (str == NULL || str_map == NULL) {
        return -1;
    }
    sem_wait(&str_map->mtx);
    if (num > str_map->max_stream) {
        ret = -2;
        goto finished;
    }
    if (num < str_map->next_stream_open) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams_del_root, &num, sizeof(u_int64_t)) != 0) {
            if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams_root, &num, sizeof(u_int64_t)) == 0) {
                *str = GQUIC_RBTREE_VALUE(rb_str);
            }
        }
        goto finished;
    }
    
    for (new_num = str_map->next_stream_open; new_num <= num; new_num++) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams_root, &new_num, sizeof(u_int64_t)) == 0) {
            gquic_stream_dtor(GQUIC_RBTREE_VALUE(rb_str));
            gquic_stream_init(GQUIC_RBTREE_VALUE(rb_str));
            GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(GQUIC_RBTREE_VALUE(rb_str), str_map, new_num);
        }
        else if (gquic_rbtree_alloc(&rb_str, sizeof(u_int64_t), sizeof(gquic_stream_t)) == 0) {
            *(u_int64_t *) GQUIC_RBTREE_KEY(rb_str) = new_num;
            gquic_stream_init(GQUIC_RBTREE_VALUE(rb_str));
            GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(GQUIC_RBTREE_VALUE(rb_str), str_map, new_num);
            gquic_rbtree_insert(&str_map->streams_root, rb_str);
        }
        else {
            ret = -3;
            goto finished;
        }
        sem_post(&str_map->new_stream_sem);

        if (new_num == num) {
            *str = GQUIC_RBTREE_VALUE(rb_str);
        }
    }
    str_map->next_stream_open = num + 1;

finished:
    sem_post(&str_map->mtx);
    return ret;
}

int gquic_inbidi_stream_map_delete_stream(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    int ret = 0;
    if (str_map == NULL) {
        return -1;
    }
    sem_wait(&str_map->mtx);

    ret = gquic_inbidi_stream_map_delete_stream_inner(str_map, num);

    sem_post(&str_map->mtx);
    return ret;
}

static int gquic_inbidi_stream_map_delete_stream_inner(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_rbtree_t *rb_str = NULL;
    gquic_rbtree_t *rb_del_str = NULL;
    gquic_frame_max_streams_t *frame = NULL;
    u_int64_t new_streams_count = 0;
    if (str_map == NULL) {
        return -1;
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams_root, &num, sizeof(u_int64_t)) != 0) {
        return -2;
    }
    if (num >= str_map->next_stream_accept) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_del_str, str_map->streams_del_root, &num, sizeof(u_int64_t)) == 0) {
            return -3;
        }
        if ((gquic_rbtree_alloc(&rb_del_str, sizeof(u_int64_t), sizeof(u_int8_t))) != 0) {
            return -4;
        }
        *(u_int64_t *) GQUIC_RBTREE_KEY(rb_del_str) = num;
        if (gquic_rbtree_insert(&str_map->streams_del_root, rb_del_str) != 0) {
            return -5;
        }
        return 0;
    }

    gquic_rbtree_remove(&str_map->streams_root, &rb_str);
    str_map->streams_count--;
    if (str_map->max_stream_count > str_map->streams_count) {
        new_streams_count = str_map->max_stream_count - str_map->streams_count;
        str_map->max_stream = str_map->next_stream_open + new_streams_count - 1;
        if ((frame = gquic_frame_max_streams_alloc()) == NULL) {
            return -6;
        }
        GQUIC_FRAME_INIT(frame);
        GQUIC_FRAME_META(frame).type = 0x12;
        frame->max = str_map->max_stream;
        GQUIC_INBIDI_STREAM_MAP_QUEUE_MAX_STREAM_ID(str_map, frame);
    }

    return 0;
}

int gquic_inbidi_stream_map_close(gquic_inbidi_stream_map_t *const str_map, const int err) {
    gquic_rbtree_t *rbt = NULL;
    gquic_list_t queue;
    if (str_map == NULL) {
        return -1;
    }
    gquic_list_head_init(&queue);
    sem_wait(&str_map->mtx);
    str_map->closed = 1;
    str_map->closed_reason = err;
    rbt = str_map->streams_root;
    if (!gquic_rbtree_is_nil(rbt)) {
        gquic_list_insert_before(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));
        *(gquic_rbtree_t **) GQUIC_LIST_LAST(&queue) = rbt;
    }
    while (!gquic_list_head_empty(&queue)) {
        rbt = GQUIC_LIST_FIRST(&queue);
        if (!gquic_rbtree_is_nil(rbt->left)) {
            gquic_list_insert_before(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));
            *(gquic_rbtree_t **) GQUIC_LIST_LAST(&queue) = rbt->left;
        }
        if (!gquic_rbtree_is_nil(rbt->right)) {
            gquic_list_insert_before(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));
            *(gquic_rbtree_t **) GQUIC_LIST_LAST(&queue) = rbt->right;
        }

        gquic_stream_close_for_shutdown(GQUIC_RBTREE_VALUE(rbt), err);

        gquic_list_release(GQUIC_LIST_FIRST(&queue));
    }
    sem_post(&str_map->mtx);
    sem_post(&str_map->new_stream_sem);
    sem_close(&str_map->new_stream_sem);

    return 0;
}

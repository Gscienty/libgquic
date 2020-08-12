/* src/stream/inbidi_stream_map.c 用于读操作的双向数据流管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "streams/inbidi_stream_map.h"
#include "frame/meta.h"
#include "frame/max_streams.h"
#include "exception.h"

static gquic_exception_t gquic_inbidi_stream_map_release_stream_inner(gquic_inbidi_stream_map_t *const, const u_int64_t);

gquic_exception_t gquic_inbidi_stream_map_init(gquic_inbidi_stream_map_t *const str_map) {
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&str_map->mtx, NULL);
    liteco_channel_init(&str_map->new_stream_chan);

    gquic_rbtree_root_init(&str_map->streams);
    str_map->streams_count = 0;
    gquic_rbtree_root_init(&str_map->del_streams);

    str_map->next_stream_accept = 0;
    str_map->next_stream_open = 0;
    str_map->max_stream = 0;
    str_map->max_stream_count = 0;

    str_map->stream_ctor.cb = NULL;
    str_map->stream_ctor.self = NULL;

    str_map->queue_max_stream_id.cb = NULL;
    str_map->queue_max_stream_id.self = NULL;

    str_map->closed = false;
    str_map->closed_reason = GQUIC_SUCCESS;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_inbidi_stream_map_ctor(gquic_inbidi_stream_map_t *const str_map,
                                               void *const new_stream_self,
                                               gquic_exception_t (*new_stream_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                               u_int64_t max_stream_count,
                                               void *const queue_max_stream_id_self,
                                               gquic_exception_t (*queue_max_stream_id_cb) (void *const, void *const)) {
    if (str_map == NULL || new_stream_self == NULL || new_stream_cb == NULL || queue_max_stream_id_self == NULL || queue_max_stream_id_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str_map->max_stream_count = max_stream_count;
    str_map->max_stream = max_stream_count;
    str_map->stream_ctor.self = new_stream_self;
    str_map->stream_ctor.cb = new_stream_cb;
    str_map->queue_max_stream_id.self = queue_max_stream_id_self;
    str_map->queue_max_stream_id.cb = queue_max_stream_id_cb;
    str_map->next_stream_open = 1;
    str_map->next_stream_accept = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_inbidi_stream_map_accept_stream(gquic_stream_t **const str,
                                                        gquic_inbidi_stream_map_t *const str_map, liteco_channel_t *const done_chan) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    u_int64_t num = 0;
    const gquic_rbtree_t *rb_str = NULL;
    const gquic_rbtree_t *rb_del_str = NULL;
    const liteco_channel_t *recv_channel = NULL;
    if (str == NULL || str_map == NULL || done_chan == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&str_map->mtx);
    for ( ;; ) {
        // 循环等待是否已存在期待的（根据num）的数据流
        num = str_map->next_stream_accept;
        if (str_map->closed) {
            GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
            goto finished;
        }
        if (gquic_rbtree_find(&rb_str, str_map->streams, &num, sizeof(u_int64_t)) == 0) {
            break;
        }
        pthread_mutex_unlock(&str_map->mtx);
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, 0, &str_map->new_stream_chan, done_chan);
        if (recv_channel == done_chan) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DONE);
        }

        pthread_mutex_lock(&str_map->mtx);
    }

    str_map->next_stream_accept++;

    if (gquic_rbtree_find(&rb_del_str, str_map->del_streams, &num, sizeof(u_int64_t)) == 0) {
        gquic_rbtree_remove(&str_map->del_streams, (gquic_rbtree_t **) &rb_del_str);
        gquic_rbtree_release((gquic_rbtree_t *) rb_del_str, NULL);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_inbidi_stream_map_release_stream_inner(str_map, num))) {
            goto finished;
        }
    }
    *str = GQUIC_RBTREE_VALUE(rb_str);
finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_inbidi_stream_map_get_or_open_stream(gquic_stream_t **const str,
                                                             gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    u_int64_t new_num = 0;
    gquic_rbtree_t *rb_str = NULL;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (num > str_map->max_stream) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_GREATE_THAN_MAX_STREAM);
        goto finished;
    }

    if (num < str_map->next_stream_open) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->del_streams, &num, sizeof(u_int64_t)) != 0) {
            if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams, &num, sizeof(u_int64_t)) == 0) {
                *str = GQUIC_RBTREE_VALUE(rb_str);
            }
        }
        goto finished;
    }
    
    for (new_num = str_map->next_stream_open; new_num <= num; new_num++) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams, &new_num, sizeof(u_int64_t)) == 0) {
            gquic_stream_dtor(GQUIC_RBTREE_VALUE(rb_str));
            gquic_stream_init(GQUIC_RBTREE_VALUE(rb_str));
            GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(GQUIC_RBTREE_VALUE(rb_str), str_map, new_num);
        }
        else if (!GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rb_str, sizeof(u_int64_t), sizeof(gquic_stream_t)))) {
            *(u_int64_t *) GQUIC_RBTREE_KEY(rb_str) = new_num;
            gquic_stream_init(GQUIC_RBTREE_VALUE(rb_str));
            GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(GQUIC_RBTREE_VALUE(rb_str), str_map, new_num);
            gquic_rbtree_insert(&str_map->streams, rb_str);
            str_map->streams_count++;
        }
        else {
            goto finished;
        }
        liteco_channel_send(&str_map->new_stream_chan, &str_map->new_stream_chan);

        if (new_num == num) {
            *str = GQUIC_RBTREE_VALUE(rb_str);
        }
    }
    str_map->next_stream_open = num + 1;

finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_inbidi_stream_map_release_stream(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    GQUIC_ASSERT_CAUSE(exception, gquic_inbidi_stream_map_release_stream_inner(str_map, num));
    pthread_mutex_unlock(&str_map->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_inbidi_stream_map_release_stream_inner(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_rbtree_t *rb_str = NULL;
    gquic_rbtree_t *rb_del_str = NULL;
    gquic_frame_max_streams_t *frame = NULL;
    u_int64_t new_streams_count = 0;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams, &num, sizeof(u_int64_t)) != 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_NOT_FOUND);
    }
    if (num >= str_map->next_stream_accept) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_del_str, str_map->del_streams, &num, sizeof(u_int64_t)) == 0) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DELETE_INCOMING_STREAM_MULTIPLE_TIMES);
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_rbtree_alloc(&rb_del_str, sizeof(u_int64_t), sizeof(u_int8_t)))
        *(u_int64_t *) GQUIC_RBTREE_KEY(rb_del_str) = num;
        GQUIC_ASSERT_FAST_RETURN(gquic_rbtree_insert(&str_map->del_streams, rb_del_str));

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    gquic_rbtree_remove(&str_map->streams, &rb_str);
    gquic_stream_dtor(GQUIC_RBTREE_VALUE(rb_str));
    gquic_rbtree_release(rb_str, NULL);
    str_map->streams_count--;
    if (str_map->max_stream_count > str_map->streams_count) {
        new_streams_count = str_map->max_stream_count - str_map->streams_count;
        str_map->max_stream = str_map->next_stream_open + new_streams_count - 1;
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_max_streams_alloc(&frame));
        GQUIC_FRAME_INIT(frame);
        GQUIC_FRAME_META(frame).type = 0x12;
        frame->max = str_map->max_stream;
        GQUIC_INBIDI_STREAM_MAP_QUEUE_MAX_STREAM_ID(str_map, frame);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_inbidi_stream_map_close(gquic_inbidi_stream_map_t *const str_map, const int err) {
    gquic_rbtree_t *payload = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    str_map->closed = true;
    str_map->closed_reason = err;

    GQUIC_RBTREE_EACHOR_BEGIN(payload, str_map->streams)
        gquic_stream_close_for_shutdown(GQUIC_RBTREE_VALUE(payload), err);
    GQUIC_RBTREE_EACHOR_END(payload)

    pthread_mutex_unlock(&str_map->mtx);
    liteco_channel_close(&str_map->new_stream_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


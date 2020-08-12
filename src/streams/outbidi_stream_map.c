/* src/stream/outbidi_stream_map.c 用于写操作的双向数据流管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "streams/outbidi_stream_map.h"
#include "frame/streams_blocked.h"
#include "frame/meta.h"

static gquic_exception_t gquic_outbidi_stream_map_open_stream_inner(gquic_stream_t **const, gquic_outbidi_stream_map_t *const);
static gquic_exception_t gquic_outbidi_stream_map_try_send_blocked_frame(gquic_outbidi_stream_map_t *const);
static gquic_exception_t gquic_outbidi_stream_map_unblock_open_sync(gquic_outbidi_stream_map_t *const);
 
gquic_exception_t gquic_outbidi_stream_map_init(gquic_outbidi_stream_map_t *const str_map) {
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&str_map->mtx, NULL);
    gquic_rbtree_root_init(&str_map->streams);
    gquic_rbtree_root_init(&str_map->open_queue);
    str_map->lowest_in_queue = 0;
    str_map->highest_in_queue = 0;
    str_map->block_sent = false;
    str_map->next_stream = 0;
    str_map->max_stream = 0;
    str_map->stream_ctor.cb = NULL;
    str_map->stream_ctor.self = NULL;
    str_map->queue_stream_id_blocked.cb = NULL;
    str_map->queue_stream_id_blocked.self = NULL;
    str_map->closed = false;
    str_map->closed_reason = GQUIC_SUCCESS;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_outbidi_stream_map_ctor(gquic_outbidi_stream_map_t *const str_map,
                                                void *const stream_ctor_self,
                                                gquic_exception_t (*stream_ctor_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                                void *const queue_stream_id_blocked_self,
                                                gquic_exception_t (*queue_stream_id_blocked_cb) (void *const, void *const)) {
    if (str_map == NULL
        || stream_ctor_self == NULL || stream_ctor_cb == NULL
        || queue_stream_id_blocked_self == NULL || queue_stream_id_blocked_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str_map->next_stream = 1;
    str_map->max_stream = (u_int64_t) -1;
    str_map->stream_ctor.cb = stream_ctor_cb;
    str_map->stream_ctor.self = stream_ctor_self;
    str_map->queue_stream_id_blocked.cb = queue_stream_id_blocked_cb;
    str_map->queue_stream_id_blocked.self = queue_stream_id_blocked_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_outbidi_stream_map_open_stream_inner(gquic_stream_t **const str, gquic_outbidi_stream_map_t *const str_map) {
    gquic_rbtree_t *stream_rbt;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_rbtree_alloc(&stream_rbt, sizeof(u_int64_t), sizeof(gquic_stream_t)));
    *str = GQUIC_RBTREE_VALUE(stream_rbt);
    *((u_int64_t *) GQUIC_RBTREE_KEY(stream_rbt)) = str_map->next_stream;
    gquic_stream_init(GQUIC_RBTREE_VALUE(stream_rbt));
    GQUIC_OUTBIDI_STREAM_MAP_STREAM_CTOR(GQUIC_RBTREE_VALUE(stream_rbt), str_map, str_map->next_stream);
    str_map->next_stream++;
    gquic_rbtree_insert(&str_map->streams, stream_rbt);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_outbidi_stream_map_open_stream(gquic_stream_t **const str, gquic_outbidi_stream_map_t *const str_map) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (str_map->closed) {
        GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
        goto finished;
    }
    if (!gquic_rbtree_is_nil(str_map->open_queue) || str_map->next_stream > str_map->max_stream || str_map->max_stream == (u_int64_t) -1) {
        gquic_outbidi_stream_map_try_send_blocked_frame(str_map);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TOO_MANY_OPEN_STREAMS);
        goto finished;
    }

    if (GQUIC_ASSERT_CAUSE(exception, gquic_outbidi_stream_map_open_stream_inner(str, str_map))) {
        goto finished;
    }
finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_outbidi_stream_map_try_send_blocked_frame(gquic_outbidi_stream_map_t *const str_map) {
    u_int64_t stream_n = 0;
    gquic_frame_streams_blocked_t *frame = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str_map->block_sent) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (str_map->max_stream != (u_int64_t) -1) {
        stream_n = str_map->max_stream;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_streams_blocked_alloc(&frame));
    GQUIC_FRAME_INIT(frame);
    GQUIC_FRAME_META(frame).type = 0x16;
    frame->limit = stream_n;
    GQUIC_OUTBIDI_STREAM_MAP_QUEUE_STREAM_ID_BLOCKED(frame, str_map);
    str_map->block_sent = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_outbidi_stream_map_open_stream_sync(gquic_stream_t **const str,
                                                            gquic_outbidi_stream_map_t *const str_map, liteco_channel_t *const done_chan) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_rbtree_t *queue_pos_rbt = NULL;
    liteco_channel_t wait_chan;
    const liteco_channel_t *recv_channel = NULL;
    if (str == NULL || str_map == NULL || done_chan == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_init(&wait_chan);

    pthread_mutex_lock(&str_map->mtx);
    if (str_map->closed) {
        GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
        goto finished;
    }
    if (gquic_rbtree_is_nil(str_map->open_queue) && str_map->next_stream <= str_map->max_stream && str_map->max_stream != (u_int64_t) -1) {
        gquic_outbidi_stream_map_open_stream_inner(str, str_map);
        goto finished;
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&queue_pos_rbt, sizeof(u_int64_t), sizeof(liteco_channel_t *)))) {
        goto finished;
    }
    *((u_int64_t *) GQUIC_RBTREE_KEY(queue_pos_rbt)) = str_map->highest_in_queue++;
    if (gquic_rbtree_is_nil(str_map->open_queue)) {
        str_map->lowest_in_queue = *((u_int64_t *) GQUIC_RBTREE_KEY(queue_pos_rbt));
    }

    *(liteco_channel_t **) GQUIC_RBTREE_VALUE(queue_pos_rbt) = &wait_chan;
    gquic_rbtree_insert(&str_map->open_queue, queue_pos_rbt);
    gquic_outbidi_stream_map_try_send_blocked_frame(str_map);

    for ( ;; ) {
        pthread_mutex_unlock(&str_map->mtx);
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, 0, &wait_chan, done_chan);
        if (recv_channel == done_chan) {
            gquic_rbtree_remove(&str_map->open_queue, &queue_pos_rbt);
            gquic_rbtree_release(queue_pos_rbt, NULL);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DONE);
        }
        pthread_mutex_lock(&str_map->mtx);

        if (str_map->closed) {
            GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
            goto finished;
        }
        if (str_map->next_stream > str_map->max_stream || str_map->max_stream == (u_int64_t) -1) {
            continue;
        }

        gquic_outbidi_stream_map_open_stream_inner(str, str_map);
        gquic_rbtree_remove(&str_map->open_queue, &queue_pos_rbt);
        gquic_rbtree_release(queue_pos_rbt, NULL);
        gquic_outbidi_stream_map_unblock_open_sync(str_map);
        goto finished;
    }

finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

static gquic_exception_t gquic_outbidi_stream_map_unblock_open_sync(gquic_outbidi_stream_map_t *const str_map) {
    u_int64_t oq = 0;
    gquic_rbtree_t *rbt = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_rbtree_is_nil(str_map->open_queue)) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    for (oq = str_map->lowest_in_queue; oq <= str_map->highest_in_queue; oq++) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, str_map->open_queue, &oq, sizeof(u_int64_t)) != 0) {
            continue;
        }
        liteco_channel_close(*(liteco_channel_t **) GQUIC_RBTREE_VALUE(rbt));
        *(liteco_channel_t **) GQUIC_RBTREE_VALUE(rbt) = NULL;
        str_map->lowest_in_queue = oq + 1;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_outbidi_stream_map_get_stream(gquic_stream_t **const str, gquic_outbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    const gquic_rbtree_t *rbt = NULL;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (num >= str_map->next_stream) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_GREATE_THAN_NEXT_STREAM);
        goto finished;
    }
    if (gquic_rbtree_find(&rbt, str_map->streams, &num, sizeof(u_int64_t)) != 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_NOT_FOUND);
        goto finished;
    }
    *str = GQUIC_RBTREE_VALUE(rbt);

finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_outbidi_stream_map_release_stream(gquic_outbidi_stream_map_t *const str_map, const u_int64_t num) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_rbtree_t *rbt = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&str_map->mtx);
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, str_map->streams, &num, sizeof(u_int64_t)) != 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_NOT_FOUND);
        goto finished;
    }
    gquic_rbtree_remove(&str_map->streams, &rbt);
    gquic_stream_dtor(GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_release(rbt, NULL);

finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_outbidi_stream_map_set_max_stream(gquic_outbidi_stream_map_t *const str_map, const u_int64_t num) {
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&str_map->mtx);
    if (str_map->max_stream != (u_int64_t) -1 && num <= str_map->max_stream) {
        goto finished;
    }
    str_map->max_stream = num;
    str_map->block_sent = false;

finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_outbidi_stream_map_close(gquic_outbidi_stream_map_t *const str_map, const gquic_exception_t err) {
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

    GQUIC_RBTREE_EACHOR_BEGIN(payload, str_map->open_queue)
        if (*(liteco_channel_t **) GQUIC_RBTREE_VALUE(payload) != NULL) {
            liteco_channel_close(*(liteco_channel_t **) GQUIC_RBTREE_VALUE(payload));
        }
    GQUIC_RBTREE_EACHOR_END(payload)

    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}


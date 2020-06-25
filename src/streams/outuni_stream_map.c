#include "streams/outuni_stream_map.h"
#include "frame/meta.h"
#include "frame/streams_blocked.h"

static int gquic_outuni_stream_map_try_send_blocked_frame(gquic_outuni_stream_map_t *const);
static int gquic_outuni_stream_map_open_stream_inner(gquic_stream_t **const, gquic_outuni_stream_map_t *const);
static int gquic_outuni_stream_map_unblock_open_sync(gquic_outuni_stream_map_t *const);

int gquic_outuni_stream_map_init(gquic_outuni_stream_map_t *const str_map) {
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&str_map->mtx, NULL);
    gquic_rbtree_root_init(&str_map->streams);
    gquic_rbtree_root_init(&str_map->open_queue);
    str_map->lowest_in_queue = 0;
    str_map->highest_in_queue = 0;
    str_map->max_stream = 0;
    str_map->next_stream = 0;
    str_map->block_sent = 0;
    str_map->stream_ctor.self = NULL;
    str_map->stream_ctor.cb = NULL;
    str_map->queue_stream_id_blocked.self = NULL;
    str_map->queue_stream_id_blocked.cb = NULL;
    str_map->closed = 0;
    str_map->closed_reason = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_outuni_stream_map_ctor(gquic_outuni_stream_map_t *const str_map,
                                 void *const stream_ctor_self,
                                 int (*stream_ctor_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                 void *const queue_stream_id_blocked_self,
                                 int (*queue_stream_id_blocked_cb) (void *const, void *const)) {
    if (str_map == NULL || stream_ctor_self == NULL || stream_ctor_cb == NULL || queue_stream_id_blocked_self == NULL || queue_stream_id_blocked_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    str_map->max_stream = (u_int64_t) -1;
    str_map->next_stream = 1;
    str_map->stream_ctor.cb = stream_ctor_cb;
    str_map->stream_ctor.self = stream_ctor_self;
    str_map->queue_stream_id_blocked.cb = queue_stream_id_blocked_cb;
    str_map->queue_stream_id_blocked.self = queue_stream_id_blocked_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_outuni_stream_map_open_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map) {
    int exception = GQUIC_SUCCESS;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (str_map->closed != GQUIC_SUCCESS) {
        GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
        goto finished;
    }
    if (!gquic_rbtree_is_nil(str_map->open_queue) || str_map->next_stream > str_map->max_stream) {
        gquic_outuni_stream_map_try_send_blocked_frame(str_map);
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_TOO_MANY_OPEN_STREAMS);
        goto finished;
    }
    GQUIC_ASSERT_CAUSE(exception, gquic_outuni_stream_map_open_stream_inner(str, str_map));

finished:
    pthread_mutex_unlock(&str_map->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_outuni_stream_map_try_send_blocked_frame(gquic_outuni_stream_map_t *const str_map) {
    u_int64_t str_num = 0;
    gquic_frame_streams_blocked_t *frame = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (str_map->block_sent) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (str_map->max_stream != (u_int64_t) -1) {
        str_num = str_map->max_stream;
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_frame_streams_blocked_alloc(&frame));
    GQUIC_FRAME_INIT(frame);
    GQUIC_FRAME_META(frame).type = 0x17;
    frame->limit = str_num;
    GQUIC_OUTUNI_STREAM_MAP_QUEUE_STREAM_ID_BLOCKED(frame, str_map);
    str_map->block_sent = 1;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_outuni_stream_map_open_stream_inner(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map) {
    int exception = GQUIC_SUCCESS;
    gquic_rbtree_t *rb_str = NULL;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_str, str_map->streams, &str_map->next_stream, sizeof(u_int64_t)) == 0) {
        gquic_stream_dtor(GQUIC_RBTREE_VALUE(rb_str));
    }
    else if (!GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rb_str, sizeof(u_int64_t), sizeof(gquic_stream_t)))) {
        *(u_int64_t *) GQUIC_RBTREE_KEY(rb_str) = str_map->next_stream;
    }
    else {
        GQUIC_PROCESS_DONE(exception);
    }

    gquic_stream_init(GQUIC_RBTREE_VALUE(rb_str));
    GQUIC_OUTUNI_STREAM_MAP_STREAM_CTOR(GQUIC_RBTREE_VALUE(rb_str), str_map, str_map->next_stream);
    str_map->next_stream++;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_outuni_stream_map_open_stream_sync(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map, liteco_channel_t *const done_chan) {
    int exception = GQUIC_SUCCESS;
    gquic_rbtree_t *queue_pos_rbt = NULL;
    const liteco_channel_t *recv_channel = NULL;
    liteco_channel_t wait_chan;
    if (str == NULL || str_map == NULL || done_chan == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_init(&wait_chan);

    pthread_mutex_lock(&str_map->mtx);
    if (str_map->closed != GQUIC_SUCCESS) {
        GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
        goto finished;
    }
    if (gquic_rbtree_is_nil(str_map->open_queue) && str_map->next_stream <= str_map->max_stream) {
        GQUIC_ASSERT_CAUSE(exception, gquic_outuni_stream_map_open_stream_inner(str, str_map));
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
    gquic_outuni_stream_map_try_send_blocked_frame(str_map);

    for ( ;; ) {
        pthread_mutex_lock(&str_map->mtx);
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, NULL, &recv_channel, 0, &wait_chan, done_chan);
        if (recv_channel == done_chan) {
            gquic_rbtree_remove(&str_map->open_queue, &queue_pos_rbt);
            gquic_rbtree_release(queue_pos_rbt, NULL);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_DONE);
        }
        pthread_mutex_unlock(&str_map->mtx);
        if (str_map->closed != GQUIC_SUCCESS) {
            GQUIC_EXCEPTION_ASSIGN(exception, str_map->closed_reason);
            goto finished;
        }
        if (str_map->next_stream > str_map->max_stream) {
            continue;
        }
        gquic_outuni_stream_map_open_stream_inner(str, str_map);
        gquic_rbtree_remove(&str_map->open_queue, &queue_pos_rbt);
        gquic_rbtree_release(queue_pos_rbt, NULL);
        gquic_outuni_stream_map_unblock_open_sync(str_map);
    }

finished:
    pthread_mutex_unlock(&str_map->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_outuni_stream_map_unblock_open_sync(gquic_outuni_stream_map_t *const str_map) {
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

int gquic_outuni_stream_map_get_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map, const u_int64_t num) {
    int exception = GQUIC_SUCCESS;
    const gquic_rbtree_t *rbt = NULL;
    if (str == NULL || str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (num >= str_map->next_stream) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_GREATE_THAN_MAX_STREAM);
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

int gquic_outuni_stream_map_release_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num) {
    int exception = GQUIC_SUCCESS;
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

int gquic_outuni_stream_map_set_max_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num) {
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    if (num <= str_map->max_stream) {
        goto finished;
    }
    str_map->max_stream = num;
    str_map->block_sent = 0;
finished:
    pthread_mutex_unlock(&str_map->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_outuni_stream_map_close(gquic_outuni_stream_map_t *const str_map, const int err) {
    gquic_rbtree_t *payload = NULL;
    if (str_map == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&str_map->mtx);
    str_map->closed = 1;
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

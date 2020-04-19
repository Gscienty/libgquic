#include "streams/framer.h"
#include "frame/meta.h"
#include "exception.h"

int gquic_framer_init(gquic_framer_t *const framer) {
    if (framer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_init(&framer->mtx, 0, 1);
    sem_init(&framer->ctrl_frame_mtx, 0, 1);
    framer->stream_getter = NULL;
    gquic_rbtree_root_init(&framer->active_streams_root);
    gquic_list_head_init(&framer->stream_queue);
    gquic_list_head_init(&framer->ctrl_frames);
    framer->stream_queue_count = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_framer_ctor(gquic_framer_t *const framer, gquic_stream_map_t *const stream_getter) {
    if (framer == NULL || stream_getter == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    framer->stream_getter = stream_getter;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_framer_queue_ctrl_frame(gquic_framer_t *const framer, void *const frame) {
    void **frame_storage = NULL;
    if (framer == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &frame_storage, sizeof(void *)));
    *frame_storage = frame;
    sem_wait(&framer->ctrl_frame_mtx);
    gquic_list_insert_before(&framer->ctrl_frames, frame_storage);
    sem_post(&framer->ctrl_frame_mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_framer_append_ctrl_frame(gquic_list_t *const frames, u_int64_t *const length, gquic_framer_t *const framer, const u_int64_t max_len) {
    int exception = GQUIC_SUCCESS;
    void **ctrl_frame_storage = NULL;
    void **frame_storage = NULL;
    u_int64_t frame_size = 0;
    if (frames == NULL || length == NULL || framer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *length = 0;
    sem_wait(&framer->ctrl_frame_mtx);
    while (!gquic_list_head_empty(&framer->ctrl_frames)) {
        ctrl_frame_storage = GQUIC_LIST_LAST(&framer->ctrl_frames);
        frame_size = GQUIC_FRAME_SIZE(*ctrl_frame_storage);
        if (*length + frame_size > max_len) {
            break;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &frame_storage, sizeof(void *)))) {
            sem_post(&framer->ctrl_frame_mtx);
            GQUIC_PROCESS_DONE(exception);
        }
        *frame_storage = *ctrl_frame_storage;
        gquic_list_insert_before(frames, frame_storage);
        *length += frame_size;
        gquic_list_release(ctrl_frame_storage);
    }
    sem_post(&framer->ctrl_frame_mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_framer_add_active_stream(gquic_framer_t *const framer, const u_int64_t id) {
    int exception = GQUIC_SUCCESS;
    gquic_rbtree_t *rb_id = NULL;
    u_int64_t *id_storage = NULL;
    if (framer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&framer->mtx);
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rb_id, framer->active_streams_root, &id, sizeof(u_int64_t)) != 0) {
        if (GQUIC_ASSERT(gquic_rbtree_alloc(&rb_id, sizeof(u_int64_t), sizeof(u_int8_t)))) {
            sem_post(&framer->mtx);
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
        }
        *(u_int64_t *) GQUIC_RBTREE_KEY(rb_id) = id;
        gquic_rbtree_insert(&framer->active_streams_root, rb_id);

        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &id_storage, sizeof(u_int64_t)))) {
            sem_post(&framer->mtx);
            GQUIC_PROCESS_DONE(exception);
        }
        *id_storage = id;
        gquic_list_insert_before(&framer->stream_queue, id_storage);

        framer->stream_queue_count++;
    }
    sem_post(&framer->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_framer_append_stream_frames(gquic_list_t *const frames, u_int64_t *const length, gquic_framer_t *const framer, const u_int64_t max_len) {
    int exception = GQUIC_SUCCESS;
    int i = 0;
    int active_streams_count = 0;
    gquic_stream_t *str = NULL;
    gquic_rbtree_t *id_rb = NULL;
    u_int64_t id = 0;
    u_int64_t remain_len = 0;
    gquic_frame_stream_t *stream_frame = NULL;
    gquic_frame_stream_t *last_stream_frame = NULL;
    int has_more_data = 0;
    u_int64_t *stream_queue_id = NULL;
    void **frame_storage = NULL;
    u_int64_t last_frame_len = 0;
    if (frames == NULL || length == NULL || framer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *length = 0;
    sem_wait(&framer->mtx);
    active_streams_count = framer->stream_queue_count;
    for (i = 0; i < active_streams_count; i++) {
        if (*length + 128 > max_len) {
            break;
        }
        id = *(u_int64_t *) GQUIC_LIST_FIRST(&framer->stream_queue);
        gquic_list_release(GQUIC_LIST_FIRST(&framer->stream_queue));
        framer->stream_queue_count--;

        if (gquic_stream_map_get_or_open_send_stream(&str, framer->stream_getter, id) != 0) {
            if (gquic_rbtree_find((const gquic_rbtree_t **) &id_rb, framer->active_streams_root, &id, sizeof(u_int64_t)) == 0) {
                gquic_rbtree_remove(&framer->active_streams_root, &id_rb);
                gquic_rbtree_release(id_rb, NULL);
            }
            continue;
        }
        remain_len = max_len - *length;
        remain_len += gquic_varint_size(&remain_len);
        has_more_data = gquic_send_stream_pop_stream_frame(&stream_frame, &str->send, remain_len);
        if (has_more_data) {
            if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &stream_queue_id, sizeof(u_int64_t)))) {
                sem_post(&framer->mtx);
                GQUIC_PROCESS_DONE(exception);
            }
            *stream_queue_id = id;
            gquic_list_insert_before(&framer->stream_queue, stream_queue_id);
        }
        else {
            if (gquic_rbtree_find((const gquic_rbtree_t **) &id_rb, framer->active_streams_root, &id, sizeof(u_int64_t)) == 0) {
                gquic_rbtree_remove(&framer->active_streams_root, &id_rb);
                gquic_rbtree_release(id_rb, NULL);
            }
        }

        if (stream_frame == NULL) {
            continue;
        }

        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &frame_storage, sizeof(void *)))) {
            sem_post(&framer->mtx);
            GQUIC_PROCESS_DONE(exception);
        }
        *frame_storage = stream_frame;
        gquic_list_insert_before(frames, frame_storage);
        *length += GQUIC_FRAME_SIZE(stream_frame);
        last_stream_frame = stream_frame;
    }
    sem_post(&framer->mtx);
    if (last_stream_frame != NULL) {
        last_frame_len = GQUIC_FRAME_SIZE(last_stream_frame);
        GQUIC_FRAME_META(last_stream_frame).type |= 0x02;
        *length += GQUIC_FRAME_SIZE(last_stream_frame) - last_frame_len;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

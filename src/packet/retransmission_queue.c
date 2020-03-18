#include "packet/retransmission_queue.h"
#include "frame/meta.h"
#include "tls/common.h"
#include "exception.h"

int gquic_retransmission_queue_init(gquic_retransmission_queue_t *const queue) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_head_init(&queue->app);
    gquic_list_head_init(&queue->handshake);
    gquic_list_head_init(&queue->handshake_crypto);
    gquic_list_head_init(&queue->initial);
    gquic_list_head_init(&queue->initial_crypto);

    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_add_initial(gquic_retransmission_queue_t *const queue, void *const frame) {
    void **frame_storage = NULL;
    if (queue == NULL || frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((frame_storage = gquic_list_alloc(sizeof(void *))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    *frame_storage = frame;
    if (GQUIC_FRAME_META(frame).type == 0x06) {
        gquic_list_insert_before(&queue->initial_crypto, frame_storage);
    }
    else {
        gquic_list_insert_before(&queue->initial, frame_storage);
    }

    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_add_handshake(gquic_retransmission_queue_t *const queue, void *const frame) {
    void **frame_storage = NULL;
    if (queue == NULL || frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((frame_storage = gquic_list_alloc(sizeof(void *))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    *frame_storage = frame;
    if (GQUIC_FRAME_META(frame).type == 0x06) {
        gquic_list_insert_before(&queue->handshake_crypto, frame_storage);
    }
    else {
        gquic_list_insert_before(&queue->handshake, frame_storage);
    }
    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_add_app(gquic_retransmission_queue_t *const queue, void *const frame) {
    void **frame_storage = NULL;
    if (queue == NULL || frame == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((frame_storage = gquic_list_alloc(sizeof(void *))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    *frame_storage = frame;
    gquic_list_insert_before(&queue->app, frame_storage);
    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_has_initial(gquic_retransmission_queue_t *const queue) {
    if (queue == NULL) {
        return 0;
    }
    return !gquic_list_head_empty(&queue->initial) || !gquic_list_head_empty(&queue->initial_crypto);
}

int gquic_retransmission_queue_has_handshake(gquic_retransmission_queue_t *const queue) {
    if (queue == NULL) {
        return 0;
    }
    return !gquic_list_head_empty(&queue->handshake) || !gquic_list_head_empty(&queue->handshake_crypto);
}

int gquic_retransmission_queue_get_initial(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size) {
    if (frame == NULL || queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (!gquic_list_head_empty(&queue->initial_crypto)) {
        if (GQUIC_FRAME_SIZE(GQUIC_LIST_FIRST(&queue->initial_crypto)) <= size) {
            *frame = *(void **) GQUIC_LIST_FIRST(&queue->initial_crypto);
            gquic_list_release(GQUIC_LIST_FIRST(&queue->initial_crypto));
            return GQUIC_SUCCESS;
        }
    }
    if (!gquic_list_head_empty(&queue->initial)) {
        if (GQUIC_FRAME_SIZE(GQUIC_LIST_FIRST(&queue->initial)) <= size) {
            *frame = *(void **) GQUIC_LIST_FIRST(&queue->initial);
            gquic_list_release(GQUIC_LIST_FIRST(&queue->initial));
        }
    }
    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_get_handshake(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size) {
    if (frame == NULL || queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (!gquic_list_head_empty(&queue->handshake_crypto)) {
        if (GQUIC_FRAME_SIZE(GQUIC_LIST_FIRST(&queue->handshake_crypto)) <= size) {
            *frame = *(void **) GQUIC_LIST_FIRST(&queue->handshake_crypto);
            gquic_list_release(GQUIC_LIST_FIRST(&queue->handshake_crypto));
            return GQUIC_SUCCESS;
        }
    }
    if (!gquic_list_head_empty(&queue->handshake)) {
        if (GQUIC_FRAME_SIZE(GQUIC_LIST_FIRST(&queue->handshake)) <= size) {
            *frame = *(void **) GQUIC_LIST_FIRST(&queue->handshake);
            gquic_list_release(GQUIC_LIST_FIRST(&queue->handshake));
        }
    }
    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_get_app(void **const frame, gquic_retransmission_queue_t *const queue, const u_int64_t size) {
    if (frame == NULL || queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (!gquic_list_head_empty(&queue->app)) {
        if (GQUIC_FRAME_SIZE(GQUIC_LIST_FIRST(&queue->app)) <= size) {
            *frame = *(void **) GQUIC_LIST_FIRST(&queue->app);
            gquic_list_release(GQUIC_LIST_FIRST(&queue->app));
        }
    }
    return GQUIC_SUCCESS;
}

int gquic_retransmission_queue_drop_packets(gquic_retransmission_queue_t *const queue, const u_int8_t enc_lv) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
        while (!gquic_list_head_empty(&queue->initial)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(&queue->initial));
            gquic_list_release(GQUIC_LIST_FIRST(&queue->initial));
        }
        while (!gquic_list_head_empty(&queue->initial_crypto)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(&queue->initial_crypto));
            gquic_list_release(GQUIC_LIST_FIRST(&queue->initial_crypto));
        }
        break;

    case GQUIC_ENC_LV_HANDSHAKE:
        while (!gquic_list_head_empty(&queue->handshake)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(&queue->handshake));
            gquic_list_release(GQUIC_LIST_FIRST(&queue->handshake));
        }
        while (!gquic_list_head_empty(&queue->handshake_crypto)) {
            gquic_frame_release(*(void **) GQUIC_LIST_FIRST(&queue->handshake_crypto));
            gquic_list_release(GQUIC_LIST_FIRST(&queue->handshake_crypto));
        }
        break;

    default:
        return GQUIC_EXCEPTION_INVALID_ENC_LV;
    }

    return GQUIC_SUCCESS;
}

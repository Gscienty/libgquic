#include "frame/meta.h"
#include "util/malloc.h"
#include "util/count_pointer.h"
#include "exception.h"

static int gquic_frame_cptr_release(void *const);

int gquic_frame_alloc(void **const result, size_t size) {
    int exception = GQUIC_SUCCESS;
    gquic_frame_meta_t *meta;
    if (result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_ALLOC_ORIG(exception, &meta, gquic_frame_meta_t, sizeof(gquic_frame_meta_t) + size, cptr, gquic_frame_cptr_release);

    meta->init_func = NULL;
    meta->deserialize_func = NULL;
    meta->dtor_func = NULL;
    meta->serialize_func = NULL;
    meta->size_func = NULL;
    meta->type = 0x00;
    meta->payload_size = size;
    meta->on_acked.self = NULL;
    meta->on_acked.cb = NULL;
    meta->on_lost.self = NULL;
    meta->on_lost.cb = NULL;

    *result = ((void *) meta) + sizeof(gquic_frame_meta_t);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_frame_release(void *const frame) {
    int exception = GQUIC_SUCCESS;
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_CPTR_TRY_RELEASE_ORIG(exception, &GQUIC_FRAME_META(frame), cptr);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_frame_assign(const void **const frame_storage, const void *frame) {
    int exception = GQUIC_SUCCESS;
    gquic_frame_meta_t *target = NULL;
    if (frame_storage == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_CPTR_ASSIGN_ORIG(exception, &target, &GQUIC_FRAME_META(frame), cptr)) {
        GQUIC_PROCESS_DONE(exception);
    }
    *frame_storage = frame;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_cptr_release(void *const meta_) {
    gquic_frame_meta_t *const meta = meta_;
    if (meta == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    meta->dtor_func(&GQUIC_FRAME_SPEC(u_int8_t, meta));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

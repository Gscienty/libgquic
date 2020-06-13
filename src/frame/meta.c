#include "frame/meta.h"
#include "util/malloc.h"
#include "util/count_pointer.h"
#include "exception.h"

static int gquic_frame_cptr_release(void *const);

int gquic_frame_alloc(void **const result, size_t size) {
    gquic_count_pointer_t *frame_cptr = NULL;
    if (result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_count_pointer_alloc(&frame_cptr, sizeof(gquic_frame_meta_t) + size, gquic_frame_cptr_release));

    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->init_func = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->deserialize_func = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->dtor_func = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->serialize_func = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->size_func = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->type = 0x00;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->payload_size = size;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->on_acked.self = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->on_acked.cb = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->on_lost.self = NULL;
    GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t)->on_lost.cb = NULL;

    *result = (void *) GQUIC_CPTR_REF(frame_cptr, gquic_frame_meta_t) + sizeof(gquic_frame_meta_t);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_frame_release(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_count_pointer_try_release(&GQUIC_CPTR_META(&GQUIC_FRAME_META(frame)));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_frame_assign(void **const frame_storage, void *frame) {
    gquic_count_pointer_t *target_cptr = NULL;
    if (frame_storage == NULL || frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_count_pointer_assign(&target_cptr, &GQUIC_CPTR_META(&GQUIC_FRAME_META(frame))));
    *frame_storage = GQUIC_CPTR_REF(target_cptr, void);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_cptr_release(void *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_FRAME_DTOR(frame);
    gquic_free(&GQUIC_FRAME_META(frame));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

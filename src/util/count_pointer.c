#include "util/count_pointer.h"
#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

int gquic_count_pointer_alloc(gquic_count_pointer_t ** const cptr_storage, size_t size, int (*release_cb) (void *const)) {
    if (cptr_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(cptr_storage, gquic_count_pointer_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc(&(*cptr_storage)->ptr, size));
    (*cptr_storage)->release_cb = release_cb;
    (*cptr_storage)->ref_count = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_count_pointer_assign(gquic_count_pointer_t **const cptr_storage, gquic_count_pointer_t *const cptr) {
    if (cptr_storage == NULL || cptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cptr->ref_count++;
    *cptr_storage = cptr;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_count_pointer_try_release(gquic_count_pointer_t *const cptr) {
    if (cptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cptr->ref_count--;
    if (cptr->ref_count == 0) {
        if (cptr->release_cb != NULL) {
            cptr->release_cb(cptr->ptr);
        }
        gquic_free(cptr->ptr);
        gquic_free(cptr);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

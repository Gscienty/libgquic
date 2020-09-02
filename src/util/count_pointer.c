/* src/util/count_pointer.c 计数指针
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "util/count_pointer.h"
#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

gquic_exception_t gquic_count_pointer_ctor(gquic_count_pointer_t *const cptr, gquic_exception_t (*release_cb) (void *const)) {
    if (cptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cptr->ref_count = 1;
    cptr->release_cb = release_cb;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_count_pointer_ref(gquic_count_pointer_t *const cptr) {
    if (cptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cptr->ref_count++;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_count_pointer_unref(gquic_count_pointer_t *const cptr) {
    if (cptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    cptr->ref_count--;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}
gquic_exception_t gquic_count_pointer_release(gquic_count_pointer_t *const cptr, void *const obj) {
    if (cptr == NULL || obj == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (cptr->ref_count == 0) {
        if (cptr->release_cb != NULL) {
            cptr->release_cb(obj);
        }
        gquic_free(obj);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

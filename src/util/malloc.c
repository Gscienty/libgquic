#include "util/malloc.h"
#include "exception.h"
#include <malloc.h>

int gquic_malloc(void **const result, size_t size) {
    if (result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *result = malloc(size);
    if (*result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_free(void *const ptr) {
    if (ptr == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    free(ptr);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

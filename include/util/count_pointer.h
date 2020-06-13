#ifndef _LIBGQUIC_UTIL_COUNT_POINTER_H
#define _LIBGQUIC_UTIL_COUNT_POINTER_H

#include <stddef.h>

typedef struct gquic_count_pointer_s gquic_count_pointer_t;
struct gquic_count_pointer_s {
    int ref_count;
    void *ptr;
    int (*release_cb) (void *const);
};

int gquic_count_pointer_alloc(gquic_count_pointer_t **const cptr_storage, size_t size, int (*release_cb) (void *const));
int gquic_count_pointer_assign(gquic_count_pointer_t **const cptr_storage, gquic_count_pointer_t *const cptr);
int gquic_count_pointer_try_release(gquic_count_pointer_t *const cptr);

#define GQUIC_CPTR_REF(cptr, type) ((cptr) == NULL ? NULL : ((type *) (cptr)->ptr))
#define GQUIC_CPTR_MALLOC_STRUCT(cptr_storage, type, release_cb) gquic_count_pointer_alloc((cptr_storage), sizeof(type), (release_cb))
#define GQUIC_CPTR_META(p) (*(gquic_count_pointer_t *) ((void *) (p) - (size_t) &((gquic_count_pointer_t *) 0)->ptr))

#endif

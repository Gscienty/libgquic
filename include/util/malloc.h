#ifndef _LIBGQUIC_UTIL_MALLOC_H
#define _LIBGQUIC_UTIL_MALLOC_H

#include <stddef.h>

int gquic_malloc(void **const result, size_t size);
int gquic_free(void *const ptr);

#define GQUIC_MALLOC_STRUCT(result, type) (gquic_malloc((void **) (result), sizeof(type)))

#endif

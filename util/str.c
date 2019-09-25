#include "util/str.h"
#include <unistd.h>
#include <malloc.h>

int gquic_str_init(gquic_str_t *str) {
    if (str == NULL) {
        return -1;
    }
    str->size = 0;
    str->val = NULL;
    return 0;
}

int gquic_str_alloc(gquic_str_t *str, size_t size) {
    if (str == NULL) {
        return -1;
    }
    if (size > 0) {
        str->val = malloc(size);
        if (str->val == NULL) {
            return -1;
        }
        str->size = size;
    }
    return 0;
}

#include "util/str.h"
#include <unistd.h>
#include <malloc.h>
#include <string.h>

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

int gquic_str_reset(gquic_str_t *str) {
    if (str == NULL) {
        return -1;
    }

    if (str->val != NULL) {
        free(str->val);
    }
    gquic_str_init(str);
    return 0;
}

int gquic_str_copy(gquic_str_t *str, const gquic_str_t *ref) {
    if (str == NULL || ref == NULL) {
        return -1;
    }
    gquic_str_init(str);
    if (gquic_str_alloc(str, GQUIC_STR_SIZE(ref)) != 0) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(str), GQUIC_STR_VAL(ref), GQUIC_STR_SIZE(str));
    return 0;
}

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
    if (str == NULL) {
        return -1;
    }
    gquic_str_init(str);
    if (GQUIC_STR_SIZE(ref) == 0) {
        return 0;
    }
    if (gquic_str_alloc(str, GQUIC_STR_SIZE(ref)) != 0) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(str), GQUIC_STR_VAL(ref), GQUIC_STR_SIZE(str));
    return 0;
}

int gquic_str_set(gquic_str_t *const str, const char *const val) {
    if (str == NULL || val == NULL) {
        return -1;
    }
    if (gquic_str_alloc(str, strlen(val)) != 0) {
        return -2;
    }
    memcpy(GQUIC_STR_VAL(str), val, GQUIC_STR_SIZE(str));
    return 0;
}

int gquic_str_test_echo(const gquic_str_t *const str) {
    if (str == NULL) {
        return -1;
    }
    u_int32_t off = 0;
    size_t i;
    printf("     ");
    for (i = 0; i < 16; i++) {
        printf("%02X ", (u_int8_t) i);
    }
    for (i = 0; i < GQUIC_STR_SIZE(str); i++) {
        if (i % 16 == 0) {
            printf("\n%04X ", off);
            off += 16;
        }
        printf("%02X ", ((unsigned char *) GQUIC_STR_VAL(str))[i]);
    }
    printf("\n");

    return 0;
}

int gquic_str_cmp(const gquic_str_t *const str_a, const gquic_str_t *const str_b) {
    if (str_a == NULL || str_b == NULL) {
        return -1;
    }
    if (GQUIC_STR_SIZE(str_a) != GQUIC_STR_SIZE(str_b)) {
        return GQUIC_STR_SIZE(str_a) - GQUIC_STR_SIZE(str_b);
    }
    size_t i;
    for (i = 0; i < GQUIC_STR_SIZE(str_a); i++) {
        int cmpret = (int16_t) ((u_int8_t *) GQUIC_STR_VAL(str_a))[i] - (int16_t) ((u_int8_t *) GQUIC_STR_VAL(str_b))[i];
        if (cmpret != 0) {
            return cmpret;
        }
    }

    return 0;
}

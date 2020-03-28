#ifndef _LIBGQUIC_UNIT_TEST_H
#define _LIBGQUIC_UNIT_TEST_H

#include "exception.h"
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>

typedef struct gquic_unit_test_s gquic_unit_test_t;
struct gquic_unit_test_s {
    const char *const title;
    int (*cb) ();
    u_int32_t magic;
};

#define GQUIC_UNIT_TEST_MAGIC 0x11b9021c
#define GQUIC_UNIT_TEST_SECTION __attribute__((used, aligned(1), section(".gquic_unit_test")))
#define GQUIC_UNIT_TEST_STRUCT_NAME(n) gquic_unit_test_struct_##n
#define GQUIC_UNIT_TEST_FUNCTION_NAME(n) gquic_unit_test_function_##n
#define GQUIC_UNIT_TEST(n) \
    int GQUIC_UNIT_TEST_FUNCTION_NAME(n)(); \
    static gquic_unit_test_t GQUIC_UNIT_TEST_STRUCT_NAME(n) GQUIC_UNIT_TEST_SECTION = { \
        .title = #n, \
        .cb = GQUIC_UNIT_TEST_FUNCTION_NAME(n), \
        .magic = GQUIC_UNIT_TEST_MAGIC \
    }; \
    int GQUIC_UNIT_TEST_FUNCTION_NAME(n)() 
#define GQUIC_UNIT_TEST_EXPECT(x) \
    if (!(x)) { \
        printf("<UNIT TEST> failure point: " __FILE__ " line - %d\n", __LINE__); \
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_UNIT_TEST_FAILED); \
    }

#endif

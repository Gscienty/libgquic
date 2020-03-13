#include "unit_test.h"
#include "util/list.h"
#include "exception.h"

GQUIC_UNIT_TEST(list_empty_test_1) {
    gquic_list_t list;
    gquic_list_head_init(&list);
    GQUIC_UNIT_TEST_EXPECT(gquic_list_head_empty(&list));
    return 0;
}

GQUIC_UNIT_TEST(list_empty_test_2) {
    gquic_list_t list;
    gquic_list_head_init(&list);
    int *i = gquic_list_alloc(sizeof(int));
    *i = 0;
    gquic_list_insert_after(&list, i);
    GQUIC_UNIT_TEST_EXPECT(!gquic_list_head_empty(&list));
    return 0;
}

GQUIC_UNIT_TEST(list_empty_test_3) {
    gquic_list_t list;
    gquic_list_head_init(&list);
    int *i = gquic_list_alloc(sizeof(int));
    *i = 0;
    gquic_list_insert_after(&list, i);
    GQUIC_UNIT_TEST_EXPECT(!gquic_list_head_empty(&list));
    gquic_list_release(GQUIC_LIST_FIRST(&list));
    GQUIC_UNIT_TEST_EXPECT(gquic_list_head_empty(&list));
    return 0;
}

GQUIC_UNIT_TEST(list_insert_after) {
    gquic_list_t list;
    gquic_list_head_init(&list);
    int i = 0;
    for (i = 0; i < 5; i++) {
        int *n = gquic_list_alloc(sizeof(int));
        *n = i;
        gquic_list_insert_after(&list, n);
    }

    int *r = NULL;
    int expect = 0;
    GQUIC_LIST_RFOREACH(r, &list) {
        GQUIC_UNIT_TEST_EXPECT(expect++ == *r);
    }

    return 0;
}

GQUIC_UNIT_TEST(list_insert_before) {
    gquic_list_t list;
    gquic_list_head_init(&list);
    int i = 0;
    for (i = 0; i < 5; i++) {
        int *n = gquic_list_alloc(sizeof(int));
        *n = i;
        gquic_list_insert_before(&list, n);
    }

    int *r = NULL;
    int expect = 0;
    GQUIC_LIST_FOREACH(r, &list) {
        GQUIC_UNIT_TEST_EXPECT(expect++ == *r);
    }

    return 0;
}

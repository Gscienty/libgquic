#include "unit_test.h"
#include "util/rbtree.h"
#include "exception.h"

GQUIC_UNIT_TEST(rbtree_init) {
    gquic_rbtree_t *rbt = NULL;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rbtree_insert_1) {
    gquic_rbtree_t *rbt = NULL;
    gquic_rbtree_t *node = NULL;

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
    *(u_int8_t *) GQUIC_RBTREE_KEY(node) = 1;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(!gquic_rbtree_is_nil(rbt));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rbtree_insert_2) {
    gquic_rbtree_t *rbt = NULL;
    gquic_rbtree_t *node = NULL;

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
    *(u_int8_t *) GQUIC_RBTREE_KEY(node) = 1;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(!gquic_rbtree_is_nil(rbt));

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
    *(u_int8_t *) GQUIC_RBTREE_KEY(node) = 2;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);

    int count = 0;
    GQUIC_RBTREE_EACHOR_BEGIN(node, rbt);
    count++;
    GQUIC_RBTREE_EACHOR_END(node);
    GQUIC_UNIT_TEST_EXPECT(count == 2);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rbtree_insert_conflict) {
    gquic_rbtree_t *rbt = NULL;
    gquic_rbtree_t *node = NULL;

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
    *(u_int8_t *) GQUIC_RBTREE_KEY(node) = 1;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(!gquic_rbtree_is_nil(rbt));

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
    *(u_int8_t *) GQUIC_RBTREE_KEY(node) = 1;
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_EXCEPTION_RBTREE_CONFLICT);

    int count = 0;
    GQUIC_RBTREE_EACHOR_BEGIN(node, rbt);
    count++;
    GQUIC_RBTREE_EACHOR_END(node);
    GQUIC_UNIT_TEST_EXPECT(count == 1);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rbtree_insert_more) {
    gquic_rbtree_t *rbt = NULL;

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    int i;
    for (i = 0; i < 10; i++) {
        gquic_rbtree_t *node = NULL;
        GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
        *(u_int8_t *) GQUIC_RBTREE_KEY(node) = i;
        GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);
    }
    GQUIC_UNIT_TEST_EXPECT(!gquic_rbtree_is_nil(rbt));

    gquic_rbtree_t *eachor = NULL;
    i = 0;
    GQUIC_RBTREE_EACHOR_BEGIN(eachor, rbt);
    i++;
    GQUIC_RBTREE_EACHOR_END(eachor);
    GQUIC_UNIT_TEST_EXPECT(i == 10);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(rbtree_insert_find) {
    gquic_rbtree_t *rbt = NULL;

    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_root_init(&rbt) == GQUIC_SUCCESS);
    GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_is_nil(rbt));

    int i;
    for (i = 0; i < 10; i++) {
        gquic_rbtree_t *node = NULL;
        GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_alloc(&node, sizeof(u_int8_t), sizeof(u_int8_t)) == GQUIC_SUCCESS);
        *(u_int8_t *) GQUIC_RBTREE_KEY(node) = i;
        GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_insert(&rbt, node) == GQUIC_SUCCESS);
    }
    GQUIC_UNIT_TEST_EXPECT(!gquic_rbtree_is_nil(rbt));

    for (i = 5; i < 15; i++) {
        const gquic_rbtree_t *node = NULL;
        if (i < 10) {
            GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_find(&node, rbt, (void *) &i, sizeof(u_int8_t)) == GQUIC_SUCCESS);
        }
        else {
            GQUIC_UNIT_TEST_EXPECT(gquic_rbtree_find(&node, rbt, (void *) &i, sizeof(u_int8_t)) == GQUIC_EXCEPTION_NOT_FOUND);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#include "util/rbtree.h"
#include "util/list.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }
    int sum = atoi(argv[1]);

    gquic_rbtree_t *root;
    gquic_rbtree_t *val;

    gquic_rbtree_root_init(&root);

    int i = 0;
    for (i = 0; i < sum; i++) {
        gquic_rbtree_alloc(&val, sizeof(int), sizeof(int));
        memcpy(GQUIC_RBTREE_KEY(val), &i, sizeof(int));
        memcpy(GQUIC_RBTREE_VALUE(val), &i, sizeof(int));

        gquic_rbtree_insert(&root, val);
    }

    gquic_list_t queue;
    gquic_list_head_init(&queue);

    gquic_list_insert_after(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));
    *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&queue)) = root;

    while (!gquic_rbtree_is_nil(root)) {
        gquic_rbtree_t *del = root;
        gquic_rbtree_remove(&root, &del);
        printf("%d\n",*(int*) GQUIC_RBTREE_KEY(del));
    }

    /*while (!gquic_list_head_empty(&queue)) {*/
        /*gquic_rbtree_t *payload = *(gquic_rbtree_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&queue));*/
        /*printf("%d\n", *(int *) GQUIC_RBTREE_VALUE(payload));*/
        /*if (!gquic_rbtree_is_nil(payload->left)) {*/
            /*gquic_list_insert_after(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));*/
            /**(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&queue)) = payload->left;*/
            /*sum++;*/
        /*}*/
        /*if (!gquic_rbtree_is_nil(payload->right)) {*/
            /*gquic_list_insert_after(&queue, gquic_list_alloc(sizeof(gquic_rbtree_t *)));*/
            /**(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&queue)) = payload->right;*/
            /*sum++;*/
        /*}*/
        /*gquic_list_remove(gquic_list_prev(GQUIC_LIST_PAYLOAD(&queue)));*/
    /*}*/

    return 0;
}

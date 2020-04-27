#include "util/heap.h"
#include "exception.h"
#include "util/malloc.h"
#include <unistd.h>

int gquic_heap_node_init(gquic_heap_node_t *const node) {
    if (node == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key_len = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_heap_node_alloc(gquic_heap_node_t **const node_storage, size_t key_len, size_t value_len) {
    if (node_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) node_storage, sizeof(gquic_heap_node_t) + key_len + value_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_heap_node_init(*node_storage));
    (*node_storage)->key_len = key_len;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

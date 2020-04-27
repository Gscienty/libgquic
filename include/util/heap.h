#ifndef _LIBGQUIC_UNIT_HEAP_H
#define _LIBGQUIC_UNIT_HEAP_H

#include <stddef.h>

typedef struct gquic_heap_node_s gquic_heap_node_t;
struct gquic_heap_node_s {
    gquic_heap_node_t *left;
    gquic_heap_node_t *right;
    gquic_heap_node_t *parent;

    size_t key_len;
};

#define GQUIC_HEAP_NODE_KEY(node) ((void *) (((void *) node) + sizeof(gquic_heap_node_t)))
#define GQUIC_HEAP_NODE_VALUE(node) ((void *) (((void *) node) + sizeof(gquic_heap_node_t) + (node)->key_len))

int gquic_heap_node_init(gquic_heap_node_t *const node);
int gquic_heap_node_alloc(gquic_heap_node_t **const node_storage, size_t key_len, size_t value_len);

#endif

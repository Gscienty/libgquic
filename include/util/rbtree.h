#ifndef _LIBGQUIC_UTIL_RBTREE_H
#define _LIBGQUIC_UTIL_RBTREE_H

#include <sys/types.h>

#define GQUIC_RBTREE_COLOR_RED 0x00
#define GQUIC_RBTREE_COLOR_BLACK 0x01
typedef u_int8_t gquic_rbtree_color_t;

typedef struct gquic_rbtree_s gquic_rbtree_t;
struct gquic_rbtree_s {
    gquic_rbtree_color_t color;
    gquic_rbtree_t *left;
    gquic_rbtree_t *right;
    gquic_rbtree_t *parent;
    
    size_t key_len;
};

#define GQUIC_RBTREE_KEY(r) (((void *) (r)) + sizeof(gquic_rbtree_t))
#define GQUIC_RBTREE_VALUE(r) (((void *) (r)) + sizeof(gquic_rbtree_t) + (r)->key_len) 

#define GQUIC_RBTREE_EACHOR_BEGIN(payload, queue) \
    gquic_list_insert_after((queue), gquic_list_alloc(sizeof(gquic_rbtree_t *))); \
    *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(queue)) = gen->active_src_conn_ids; \
    while (!gquic_list_head_empty(queue)) { \
        (payload) = *(gquic_rbtree_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(queue));

#define GQUIC_RBTREE_EACHOR_END(payload, queue) \
        if (!gquic_rbtree_is_nil((payload)->left)) { \
            gquic_list_insert_after((queue), gquic_list_alloc(sizeof(gquic_rbtree_t *))); \
            *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(queue)) = (payload)->left; \
        } \
        if (!gquic_rbtree_is_nil((payload)->right)) { \
            gquic_list_insert_after((queue), gquic_list_alloc(sizeof(gquic_rbtree_t *))); \
            *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(queue)) = (payload)->right; \
        } \
        gquic_list_remove(gquic_list_prev(GQUIC_LIST_PAYLOAD(queue))); \
    }

int gquic_rbtree_root_init(gquic_rbtree_t **const root);
int gquic_rbtree_alloc(gquic_rbtree_t **const rb, const size_t key_len, const size_t val_len);
int gquic_rbtree_release(gquic_rbtree_t *const rb, int (*release_val)(void *const));
int gquic_rbtree_insert(gquic_rbtree_t **const root, gquic_rbtree_t *const node);
int gquic_rbtree_remove(gquic_rbtree_t **const root, gquic_rbtree_t **const node);
int gquic_rbtree_is_nil(gquic_rbtree_t *const node);
int gquic_rbtree_find(const gquic_rbtree_t **const ret, const gquic_rbtree_t *const root, const void *key, const size_t key_len);


#endif

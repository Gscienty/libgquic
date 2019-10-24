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

int gquic_rbtree_root_init(gquic_rbtree_t **root);
int gquic_rbtree_alloc(gquic_rbtree_t **const rb, const size_t key_len, const size_t val_len);
int gquic_rbtree_release(gquic_rbtree_t *const rb, int (*release_val)(void *const));
int gquic_rbtree_insert(gquic_rbtree_t **root, gquic_rbtree_t *node);
int gquic_rbtree_remove(gquic_rbtree_t **const root, gquic_rbtree_t **const node);
int gquic_rbtree_is_nil(gquic_rbtree_t *node);


#endif

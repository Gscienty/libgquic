/* include/util/rbtree.h 红黑树
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_RBTREE_H
#define _LIBGQUIC_UTIL_RBTREE_H

#include "util/list.h"
#include <sys/types.h>

#define GQUIC_RBTREE_COLOR_RED 0x00
#define GQUIC_RBTREE_COLOR_BLACK 0x01
typedef u_int8_t gquic_rbtree_color_t;

/**
 * 红黑树节点
 */
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

#define GQUIC_RBTREE_EACHOR_BEGIN(payload, root) \
{ \
    gquic_list_t __$rbt_queue; \
    gquic_list_head_init(&__$rbt_queue); \
    void *__$tmp; \
    if (!gquic_rbtree_is_nil((root))) { \
        gquic_list_alloc(&__$tmp, sizeof(gquic_rbtree_t *)); \
        gquic_list_insert_after((&__$rbt_queue), __$tmp); \
        *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&__$rbt_queue)) = (root); \
    } \
    while (!gquic_list_head_empty(&__$rbt_queue)) { \
        do { \
            (payload) = *(gquic_rbtree_t **) gquic_list_prev(GQUIC_LIST_PAYLOAD(&__$rbt_queue));


#define GQUIC_RBTREE_EACHOR_END(payload) \
        } while (0);    \
        if (!gquic_rbtree_is_nil((payload)->left)) { \
            gquic_list_alloc(&__$tmp, sizeof(gquic_rbtree_t *)); \
            gquic_list_insert_after((&__$rbt_queue), __$tmp); \
            *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&__$rbt_queue)) = (payload)->left; \
        } \
        if (!gquic_rbtree_is_nil((payload)->right)) { \
            gquic_list_alloc(&__$tmp, sizeof(gquic_rbtree_t *)); \
            gquic_list_insert_after((&__$rbt_queue), __$tmp); \
            *(gquic_rbtree_t **) gquic_list_next(GQUIC_LIST_PAYLOAD(&__$rbt_queue)) = (payload)->right; \
        } \
        gquic_list_remove(gquic_list_prev(GQUIC_LIST_PAYLOAD(&__$rbt_queue))); \
    } \
}

/**
 * 初始化红黑树根节点
 *
 * @param root: 红黑树根节点
 *
 * @return: exception
 */
gquic_exception_t gquic_rbtree_root_init(gquic_rbtree_t **const root);

/**
 * 申请一个红黑树节点
 *
 * @param key_len: 键长度
 * @param val_len: 值长度
 *
 * @return rb: 红黑树节点
 * @return: exception
 */
gquic_exception_t gquic_rbtree_alloc(gquic_rbtree_t **const rb, const size_t key_len, const size_t val_len);

/**
 * 释放一个红黑树节点
 *
 * @param rb: 红黑树节点
 * @param release_val: 对值释放的回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_rbtree_release(gquic_rbtree_t *const rb, gquic_exception_t (*release_val)(void *const));

/**
 * 向红黑树中插入一个节点
 *
 * @param root: 红黑树根节点
 * @param node: 待插入的红黑树节点
 *
 * @return: exception
 */
gquic_exception_t gquic_rbtree_insert(gquic_rbtree_t **const root, gquic_rbtree_t *const node);
gquic_exception_t gquic_rbtree_insert_cmp(gquic_rbtree_t **const root, gquic_rbtree_t *const node, gquic_exception_t (*key_cmp) (void *const, void *const));

/**
 * 从红黑树中删除一个节点
 *
 * @param root: 红黑树根节点
 * @param node: 待删除的红黑树节点
 */
gquic_exception_t gquic_rbtree_remove(gquic_rbtree_t **const root, gquic_rbtree_t **const node);

/**
 * 判断红黑树是否为空
 *
 * @param node: 红黑树根节点
 */
bool gquic_rbtree_is_nil(gquic_rbtree_t *const node);

/**
 * 根据key值查找红黑树中的某个节点
 *
 * @param root: 红黑树根节点
 * @param key: 键
 * @param key_len: 键长
 *
 * @return ret: 查找到的红黑树节点
 * @return: exception
 */
gquic_exception_t gquic_rbtree_find(const gquic_rbtree_t **const ret, const gquic_rbtree_t *const root, const void *key, const size_t key_len);
gquic_exception_t gquic_rbtree_find_cmp(const gquic_rbtree_t **const ret, const gquic_rbtree_t *const root, void *key, gquic_exception_t (key_cmp) (void *const, void *const));


#endif

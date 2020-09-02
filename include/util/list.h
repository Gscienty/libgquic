/* include/util/list.h 双向链表
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_LIST_H
#define _LIBGQUIC_UTIL_LIST_H

#include "exception.h"
#include <unistd.h>
#include <stdbool.h>

/**
 * 双向链表
 */
typedef struct gquic_list_s gquic_list_t;
struct gquic_list_s {
    gquic_list_t *prev;
    gquic_list_t *next;
    size_t payload_size;
};

#define GQUIC_LIST_PAYLOAD(p) (((void *) (p)) + (sizeof(gquic_list_t)))
#define GQUIC_LIST_META(p) (*((gquic_list_t *) (((void *) (p)) - (sizeof(gquic_list_t)))))
#define GQUIC_LIST_FIRST(h) (gquic_list_next(GQUIC_LIST_PAYLOAD((h))))
#define GQUIC_LIST_LAST(h) (gquic_list_prev(GQUIC_LIST_PAYLOAD((h))))
#define GQUIC_LIST_FOREACH(p, h) \
    for (({\
          gquic_list_t *_$check = NULL;\
          (void) (_$check == (h));\
          (p) = GQUIC_LIST_FIRST((h));\
          }); &GQUIC_LIST_META((p)) != (h) && (h) != NULL; (p) = gquic_list_next((p)))
#define GQUIC_LIST_RFOREACH(p, h) \
    for (({\
          gquic_list_t *_$check = NULL;\
          (void) (_$check == (h));\
          (p) = GQUIC_LIST_LAST((h));\
          }); (p) != GQUIC_LIST_PAYLOAD((h)); (p) = gquic_list_prev((p)))

/**
 * 申请一个链表元素
 *
 * @param size: 链表元素大小
 * 
 * @return result: 链表元素
 * @return: exception
 */
gquic_exception_t gquic_list_alloc(void **const result, size_t size);

/**
 * 释放一个链表元素
 *
 * @param list: 链表元素
 *
 * @return: exception
 */
gquic_exception_t gquic_list_release(void *const list);

/**
 * 初始化一个链表头部
 *
 * @param head: 链表头部
 *
 * @return: exception
 */
gquic_exception_t gquic_list_head_init(gquic_list_t *head);

/**
 * 判断一个链表是否为空
 *
 * @param head: 链表头部
 *
 * @return: 是否为空链表
 */
bool gquic_list_head_empty(const gquic_list_t *head);

/**
 * 将一个点插在链表的某个点之前
 *
 * @param ref: 链表中的元素
 * @param node: 待插入的元素
 *
 * @return: exception
 */
gquic_exception_t gquic_list_insert_after(gquic_list_t *ref, void *const node);

/**
 * 将一个点插在链表的某个点之后
 *
 * @param ref: 链表中的元素
 * @param node: 待插入的元素
 *
 * @return: exception
 */
gquic_exception_t gquic_list_insert_before(gquic_list_t *ref, void *const node);

/**
 * 获取链表的下一个元素
 *
 * @param node: 链表中的元素
 *
 * @return: 下一个元素
 */
void *gquic_list_next(void *const node);

/**
 * 获取链表的上一个元素
 *
 * @param node: 链表中的元素
 *
 * @return: 上一个元素
 */
void *gquic_list_prev(void *const node);

/**
 * 从链表中移除一个元素
 *
 * @param node: 待删除的元素
 *
 * @return: exception
 */
gquic_exception_t gquic_list_remove(void *const node);

/**
 * 拷贝链表
 *
 * @param list: 新链表
 * @param ref: 被拷贝的链表
 * @param fptr: 拷贝函数
 *
 * @return: exception
 */
gquic_exception_t gquic_list_copy(gquic_list_t *list, const gquic_list_t *ref, gquic_exception_t (*fptr) (void *const, const void *const));

#endif

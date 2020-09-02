/* include/util/count_pointer.h 计数指针
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_COUNT_POINTER_H
#define _LIBGQUIC_UTIL_COUNT_POINTER_H

#include "util/malloc.h"
#include "exception.h"
#include <stddef.h>

/**
 * 计数指针
 */
typedef struct gquic_count_pointer_s gquic_count_pointer_t;
struct gquic_count_pointer_s {
    int ref_count;
    gquic_exception_t (*release_cb) (void *const);
};

/**
 * 构造一个技术指针
 *
 * @param cptr: 计数指针
 * @param release_cb: 释放内存的回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_count_pointer_ctor(gquic_count_pointer_t *const cptr, gquic_exception_t (*release_cb) (void *const));

/**
 * 计数指针添加一次引用
 *
 * @param cptr: 计数指针
 *
 * @return: exception
 */
gquic_exception_t gquic_count_pointer_ref(gquic_count_pointer_t *const cptr);

/**
 * 计数指针取消一次引用
 *
 * @param cptr: 计数指针
 *
 * @return: exception
 */
gquic_exception_t gquic_count_pointer_unref(gquic_count_pointer_t *const cptr);

/**
 * 尝试释放引用指针
 *
 * @param cptr: 引用指针
 * @param obj: 引用指针指向的对象
 *
 * @return: exception
 */
gquic_exception_t gquic_count_pointer_release(gquic_count_pointer_t *const cptr, void *const obj);

#define GQUIC_CPTR_TYPE(type) type *

#define GQUIC_CPTR_CONTAIN_OF(ptr, type, ptr_mem) ((type *) (((void *) (ptr)) - ((size_t) (&((type *) 0)->ptr_mem))))

#define GQUIC_CPTR_ALLOC_ORIG(exception, result, type, size, cptr_mem, release_cb) \
    (GQUIC_ASSERT_CAUSE(exception, gquic_malloc((void **) result, size)) || \
     GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_ctor(&((type *) *(result))->cptr_mem, release_cb)))

#define GQUIC_CPTR_ALLOC(exception, result, type, ptr_mem, cptr_mem, release_cb) \
    ({ \
     type *_$cptr_obj = NULL; \
     GQUIC_ASSERT_CAUSE(exception, GQUIC_MALLOC_STRUCT(&_$cptr_obj, type)) || \
     GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_ctor(&_$cptr_obj->cptr_mem, release_cb)) || \
     ({ *(result) = &_$cptr_obj->ptr_mem; }); \
     })

#define GQUIC_CPTR_TRY_RELEASE_ORIG(exception, ptr, cptr_mem) \
    (GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_unref(&(ptr)->cptr_mem)) || \
     GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_release(&(ptr)->cptr_mem, (ptr))))

#define GQUIC_CPTR_TRY_RELEASE(exception, ptr, type, ptr_mem, cptr_mem) \
    GQUIC_CPTR_TRY_RELEASE_ORIG(exception, GQUIC_CPTR_CONTAIN_OF(ptr, type, ptr_mem), cptr_mem)

#define GQUIC_CPTR_ASSIGN(exception, target, ptr, type, ptr_mem, cptr_mem) \
    ({ \
     *(target) = ptr; \
     GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_ref(&GQUIC_CPTR_CONTAIN_OF(ptr, type, ptr_mem)->cptr_mem)); \
     })

#define GQUIC_CPTR_ASSIGN_ORIG(exception, target, ptr, cptr_mem) \
    ({ \
     *(target) = ptr; \
     GQUIC_ASSERT_CAUSE(exception, gquic_count_pointer_ref(&(ptr)->cptr_mem)); \
     })

#endif

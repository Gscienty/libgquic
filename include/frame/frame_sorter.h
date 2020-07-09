/* include/frame/frame_sorter.h frame_sorter 定义
 * 用于拼装frame数据
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_FRAME_SORTER_H
#define _LIBGQUIC_FRAME_FRAME_SORTER_H

#include "util/str.h"
#include "util/rbtree.h"
#include "util/list.h"
#include "exception.h"

typedef struct gquic_byte_interval_s gquic_byte_interval_t;
struct gquic_byte_interval_s {
    u_int64_t start;
    u_int64_t end;
};

typedef struct gquic_frame_sorter_entry_s gquic_frame_sorter_entry_t;
struct gquic_frame_sorter_entry_s {
    gquic_str_t data;
    struct {
        void *self;
        int (*cb) (void *const);
    } done_cb;
};

#define GQUIC_FRAME_SORTER_ENTRY_DONE(entry) ((entry)->done_cb.self != NULL \
                                              ? (entry)->done_cb.cb((entry)->done_cb.self) \
                                              : GQUIC_EXCEPTION_NOT_IMPLEMENTED);

gquic_exception_t gquic_frame_sorter_entry_init(gquic_frame_sorter_entry_t *const entry);

typedef struct gquic_frame_sorter_s gquic_frame_sorter_t;
struct gquic_frame_sorter_s {
    gquic_rbtree_t *root; /* u_int64_t: gquic_frame_sorter_entry_t */
    u_int64_t read_pos;
    int gaps_count;
    gquic_list_t gaps;
};

/**
 * 初始化frame_sorter
 *
 * @param sorter: sorter
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_sorter_init(gquic_frame_sorter_t *const sorter);

/**
 * 构造frame_sorter
 *
 * @param sorter: sorter
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_sorter_ctor(gquic_frame_sorter_t *const sorter);

/**
 * 析构frame_sorter
 *
 * @param sorter: sorter
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_sorter_dtor(gquic_frame_sorter_t *const sorter);

/**
 * 向frame_sorter添加数据
 *
 * @param sorter: sorter
 * @param data: 添加的数据
 * @param off: 数据偏移量
 * @param done_cb: 当前数据块处理完毕的回调函数
 * @param done_cb_self: 当前数据块处理完毕后的回调函数self参数
 *
 * @return: exception
 */
gquic_exception_t gquic_frame_sorter_push(gquic_frame_sorter_t *const sorter,
                                          const gquic_str_t *const data, const u_int64_t off, int (*done_cb) (void *const), void *const done_cb_self);

/**
 * 从frame_sorter中获取数据
 *
 * @param: sorter: sorter
 * 
 * @return off: 数据块偏移量
 * @return data: 数据块
 * @return done_cb: 数据块处理完毕的回调函数
 * @return done_cb_self: 数据块处理完毕后的回调函数self参数
 * @return: exception
 */
gquic_exception_t gquic_frame_sorter_pop(u_int64_t *const off, gquic_str_t *const data, int (**done_cb) (void *const), void **done_cb_self,
                                         gquic_frame_sorter_t *const sorter);

#endif

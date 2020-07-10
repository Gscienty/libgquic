/* include/frame/meta.h 基础frame定义
 * 该模块用于统一管理frame使用，作为所有frame的抽象类
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_META_H
#define _LIBGQUIC_FRAME_META_H

#include "exception.h"
#include "util/str.h"
#include "util/count_pointer.h"
#include <sys/types.h>

typedef struct gquic_frame_meta_s gquic_frame_meta_t;
struct gquic_frame_meta_s {
    int (*init_func) (void *const);
    size_t (*size_func) (const void *const);
    int (*serialize_func) (const void *const, gquic_writer_str_t *const);
    int (*deserialize_func) (void *const, gquic_reader_str_t *const);
    int (*dtor_func) (void *const);
    u_int8_t type;

    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } on_acked;

    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } on_lost;

    size_t payload_size;

    gquic_count_pointer_t cptr;
};

/**
 * 获取frame的抽象类meta
 *
 * @param ptr: frame
 * 
 * @return: meta
 */
#define GQUIC_FRAME_META(ptr) (*((gquic_frame_meta_t *) (((void *) ptr) - sizeof(gquic_frame_meta_t))))

/**
 * 从frame的抽象类meta获取具体的frame
 *
 * @param frame_type_t: frame类型
 * @param ptr: frame
 * 
 * @return: frame
 */
#define GQUIC_FRAME_SPEC(frame_type_t, ptr) (*((frame_type_t *) (((void *) ptr) + sizeof(gquic_frame_meta_t))))

/**
 * 初始化frame
 *
 * @param ptr: frame
 * 
 * @return: exception
 */
#define GQUIC_FRAME_INIT(ptr) (GQUIC_FRAME_META((ptr)).init_func((ptr)))

/**
 * 获取frame序列化后的数据大小
 *
 * @param ptr: frame
 * 
 * @return: frame序列化后的数据大小
 */
#define GQUIC_FRAME_SIZE(ptr) (GQUIC_FRAME_META((ptr)).size_func((ptr)))

/**
 * frame序列化
 *
 * @param ptr: frame
 * @param writer: writer
 *
 * @return: exception
 */
#define GQUIC_FRAME_SERIALIZE(ptr, writer) (GQUIC_FRAME_META((ptr)).serialize_func((ptr), (writer)))

/**
 * frame 反序列化
 *
 * @param reader: reader
 *
 * @return ptr: 反序列化的frame
 * @return: exception
 */
#define GQUIC_FRAME_DESRIALIZE(ptr, reader) (GQUIC_FRAME_META((ptr)).deserialize_func((ptr), (reader)))

/**
 * 析构frame
 *
 * @param ptr: frame
 * 
 * @return: exception
 */
#define GQUIC_FRAME_DTOR(ptr) (GQUIC_FRAME_META((ptr)).dtor_func((ptr)))

/**
 * 当frame确认接收后的事件回调
 *
 * @param ptr: frame
 * 
 * @return: exception
 */
#define GQUIC_FRAME_ON_ACKED(ptr) (GQUIC_FRAME_META((ptr)).on_acked.cb == NULL \
                                   ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                                   : GQUIC_FRAME_META((ptr)).on_acked.cb((GQUIC_FRAME_META((ptr)).on_acked.self), (ptr)))

/**
 * 当frame确认丢失后的事件回调
 *
 * @param ptr: frame
 * 
 * @return exception
 */
#define GQUIC_FRAME_ON_LOST(ptr) (GQUIC_FRAME_META((ptr)).on_lost.cb == NULL \
                                  ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
                                  : (GQUIC_FRAME_META((ptr)).on_lost.cb((GQUIC_FRAME_META((ptr)).on_lost.self), (ptr))))

/**
 * 生成抽象frame
 *
 * @param size: frame size
 * 
 * @return result: frame
 * @return: exception
 */
gquic_exception_t gquic_frame_alloc(void **const result, size_t size);

/**
 * 释放frame
 *
 * @param frame: frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_release(void *const frame);

/**
 * 将frame赋值给新的frame指针
 *
 * @param frame: frame
 * 
 * @return frame_storage: frame
 * @return exception
 */
gquic_exception_t gquic_frame_assign(const void **const frame_storage, const void *frame);

/**
 * 生成抽象frame
 *
 * @param type: frame类型
 *
 * @return result: frame
 * @return exception
 */
#define GQUIC_FRAME_ALLOC(result, type) (gquic_frame_alloc((void **) (result), sizeof(type)))

#endif


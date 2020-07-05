/* include/event/epoll.h 对epoll的event封装定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_EVENT_EPOLL_H
#define _LIBGQUIC_EVENT_EPOLL_H

#include "exception.h"
#include <sys/epoll.h>

// epoll最大连接数
#define GQUIC_EVENT_EPOLL_CONNECTION_COUNT 8

// epoll最大事件容量
#define GQUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT 8

// epoll无效fd
#define GQUIC_INVALID_EPOLL_FD -1

/** 
 * epoll event封装
 */
typedef struct gquic_event_epoll_s gquic_event_epoll_t;
struct gquic_event_epoll_s {

    // epoll 事件
    struct epoll_event actives[GQUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT];

    // epoll fd
    int ep;

    // epoll 事件回调
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } process_cb;
};

/**
 * 触发epoll event 注册的事件回调
 */
#define GQUIC_EVENT_EPOLL_PROCESS(event, obj) \
    ((event)->process_cb.self == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (event)->process_cb.cb((event)->process_cb.self, (obj)))

/**
 * 初始化 epoll event
 * 
 * @param event: event
 * 
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_init(gquic_event_epoll_t *const event);

/**
 * 构造epoll event
 *
 * @param event: event
 * @param process_self: 事件回调self参数
 * @param process_cb: 回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_ctor(gquic_event_epoll_t *const event, void *const process_self, int (*process_cb) (void *const, void *const));

/**
 * 析构epoll event
 * 
 * @param event: event
 * 
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_dtor(gquic_event_epoll_t *const event);

/**
 * 向epoll event添加一个监听的fd
 *
 * @param event: event
 * @param fd: 待添加的fd
 * @param: obj: 注册到epoll中的data, 作为回调事件函数的第二个参数
 *
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_add(gquic_event_epoll_t *const event, int fd, void *const obj);

/**
 * 从epoll event移除指定的fd
 *
 * @param event: event
 * @param fd: 待移除的fd
 *
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_remove(gquic_event_epoll_t *const event, int fd);


/**
 * 监听epoll event事件
 *
 * @param: event: event
 * @param timeout: 监听超时时间
 *
 * @return: exception
 */
gquic_exception_t gquic_event_epoll_process(gquic_event_epoll_t *const event, const u_int64_t timeout);

#endif

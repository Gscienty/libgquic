/* src/packet/multiplexer.c UDP到QUIC的复用模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "event/epoll.h"
#include "packet/multiplexer.h"
#include "util/rbtree.h"
#include "exception.h"
#include "coglobal.h"
#include "log.h"
#include <pthread.h>
#include <stdbool.h>

#define GQUIC_DEFAULT_EPOLL_CONNECTION_SIZE 8

typedef struct gquic_multiplexer_s gquic_multiplexer_t;
struct gquic_multiplexer_s {

    pthread_mutex_t mtx;

    // UDP到QUIC的映射关系表
    gquic_rbtree_t *conns;

    // epoll
    gquic_event_epoll_t epoll;

    // 负责监听epoll传入的事件
    pthread_t thread;
};

/**
 * 初始化复用模块
 */
static void gquic_init_multiplexer();

/**
 * 监听epoll事件的线程
 */
static void *gquic_multiplexer_thread(void *const);

/**
 * 处理epoll事件的操作
 *
 * @param handler_: packet handler
 * 
 * @return: exception
 */
static gquic_exception_t gquic_multiplexer_recv_event(void *const, void *const handler_);

static bool __inited = false;
static gquic_multiplexer_t __ins;

static void gquic_init_multiplexer() {
    if (__inited == false) {
        pthread_mutex_init(&__ins.mtx, NULL);
        gquic_rbtree_root_init(&__ins.conns);

        gquic_event_epoll_init(&__ins.epoll);
        gquic_event_epoll_ctor(&__ins.epoll, &__ins, gquic_multiplexer_recv_event);

        pthread_create(&__ins.thread, NULL, gquic_multiplexer_thread, NULL);
        __inited = true;
    }
}

gquic_exception_t gquic_multiplexer_add_conn(gquic_packet_handler_map_t **const handler_storage,
                                             const int conn_fd, const int conn_id_len, const gquic_str_t *const stateless_reset_token) {
    int exception = GQUIC_SUCCESS;
    gquic_rbtree_t *rbt = NULL;
    if (handler_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_init_multiplexer();

    pthread_mutex_lock(&__ins.mtx);
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, __ins.conns, &conn_fd, sizeof(int)) != 0) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rbt, sizeof(int), sizeof(gquic_packet_handler_map_t)))) {
            goto finished;
        }
        *(int *) GQUIC_RBTREE_KEY(rbt) = conn_fd;
        gquic_packet_handler_map_init(GQUIC_RBTREE_VALUE(rbt));
        gquic_packet_handler_map_ctor(GQUIC_RBTREE_VALUE(rbt), conn_fd, conn_id_len, stateless_reset_token);
        gquic_rbtree_insert(&__ins.conns, rbt);

        gquic_event_epoll_add(&__ins.epoll, conn_fd, GQUIC_RBTREE_VALUE(rbt));
    }
    if (((gquic_packet_handler_map_t *) GQUIC_RBTREE_VALUE(rbt))->conn_id_len != conn_id_len) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_RECV_CONN_ID_CONFLICT);
        goto finished;
    }
    if (GQUIC_STR_SIZE(stateless_reset_token) != 0
        && gquic_str_cmp(stateless_reset_token, &((gquic_packet_handler_map_t *) GQUIC_RBTREE_VALUE(rbt))->stateless_reset_key) != 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_CONN_CANNOT_USE_DIFF_STATELESS_TOKEN);
        goto finished;
    }
    *handler_storage = GQUIC_RBTREE_VALUE(rbt);

finished:
    pthread_mutex_unlock(&__ins.mtx);
    GQUIC_PROCESS_DONE(exception);
}

gquic_exception_t gquic_multiplexer_remove_conn(const int conn_fd) {
    gquic_exception_t exception = GQUIC_SUCCESS;
    gquic_rbtree_t *rbt = NULL;
    gquic_init_multiplexer();
    pthread_mutex_lock(&__ins.mtx);

    gquic_event_epoll_remove(&__ins.epoll, conn_fd);
    
    if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, __ins.conns, &conn_fd, sizeof(int)) != 0) {
        GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_CONN_UNKNOW);
        goto finished;
    }
    gquic_rbtree_remove(&__ins.conns, &rbt);
    gquic_packet_handler_map_dtor(GQUIC_RBTREE_VALUE(rbt));
    gquic_rbtree_release(rbt, NULL);

finished:
    pthread_mutex_unlock(&__ins.mtx);
    GQUIC_PROCESS_DONE(exception);
}

static void *gquic_multiplexer_thread(void *const _) {
    (void) _;

    for ( ;; ) {
        gquic_event_epoll_process(&__ins.epoll, 1000);
    }

    return NULL;
}

static gquic_exception_t gquic_multiplexer_recv_event(void *const _, void *const handler_) {
    (void) _;
    gquic_packet_handler_map_t *const handler = handler_;
    if (handler_ == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_DEBUG, "multiplexer received event");

    liteco_channel_send(&handler->recv_event_chan, &handler->recv_event_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

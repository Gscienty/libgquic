/* src/packet/packet_handler_map.c 用于UDP到QUIC的数据包分发
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/packet_handler_map.h"
#include "packet/handler.h"
#include "packet/multiplexer.h"
#include "net/conn.h"
#include "util/time.h"
#include "util/malloc.h"
#include "coglobal.h"
#include "exception.h"
#include "log.h"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <errno.h>
#include <string.h>

typedef struct __send_stateless_reset_param_s __send_stateless_reset_param_t;
struct __send_stateless_reset_param_s {
    gquic_packet_handler_map_t *handler;
    gquic_received_packet_t *recv_packet;
};

typedef struct __reset_token_param_s __reset_token_param_t;
struct __reset_token_param_s {
    gquic_packet_handler_t *handler;
    int err;
};

typedef struct gquic_phm_retire_timeout_param_s gquic_phm_retire_timeout_param_t;
struct gquic_phm_retire_timeout_param_s {
    gquic_packet_handler_map_t *handler;
    gquic_str_t conn_id;
};

typedef struct __retire_reset_token_timeout_param_s __retire_reset_token_timeout_param_t;
struct __retire_reset_token_timeout_param_s {
    gquic_packet_handler_map_t *handler;
    gquic_str_t token;
};

typedef struct __replace_with_closed_timeout_param_s __replace_with_closed_timeout_param_t;
struct __replace_with_closed_timeout_param_s {
    gquic_packet_handler_map_t *handler;
    gquic_packet_handler_t *ph;
    gquic_str_t conn_id;
};

static gquic_exception_t gquic_packet_handler_map_listen(void *const handler_);
static gquic_exception_t gquic_packet_handler_map_try_send_stateless_reset_co(void *const handler_);
static bool gquic_packet_handler_map_try_handle_stateless_reset(gquic_packet_handler_map_t *const handler_, const gquic_str_t *const data);
static gquic_exception_t gquic_packet_handler_rb_str_cmp(void *const a, void *const b);
static gquic_exception_t gquic_packet_handler_map_reset_token_destroy_co(void *const handler_);
static gquic_exception_t gquic_retire_timeout_cb(void *const handler_);
static gquic_exception_t gquic_replace_with_closed_timeout_cb(void *const handler_);
static gquic_exception_t gquic_retire_reset_token_timeout_cb(void *const handler_);
static gquic_exception_t gquic_packet_handler_map_listen_close(gquic_packet_handler_map_t *const handler, const int err);

gquic_exception_t gquic_packet_unknow_packet_handler_init(gquic_packet_unknow_packet_handler_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->handle_packet.cb = NULL;
    handler->handle_packet.self = NULL;
    handler->set_close_err.cb = NULL;
    handler->set_close_err.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_init(gquic_packet_handler_map_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&handler->mtx, NULL);
    handler->conn_fd = 0;
    handler->conn_id_len = 0;
    gquic_rbtree_root_init(&handler->handlers);
    gquic_rbtree_root_init(&handler->reset_tokens);
    handler->server = NULL;

    liteco_channel_init(&handler->listen_chan);
    handler->closed = false;

    liteco_channel_init(&handler->recv_event_chan);
    liteco_channel_init(&handler->close_chan);

    handler->delete_retired_session_after = 0;

    handler->stateless_reset_enabled = false;
    gquic_str_init(&handler->stateless_reset_key);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_ctor(gquic_packet_handler_map_t *const handler,
                                                const int conn_fd, const int conn_id_len, const gquic_str_t *const stateless_reset_token) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    handler->conn_fd = conn_fd;
    handler->conn_id_len = conn_id_len;
    handler->delete_retired_session_after = 5 * 1000 * 1000;
    handler->stateless_reset_enabled = GQUIC_STR_SIZE(stateless_reset_token) > 0;
    gquic_str_copy(&handler->stateless_reset_key, stateless_reset_token);
    GQUIC_ASSERT_FAST_RETURN(gquic_coglobal_execute(gquic_packet_handler_map_listen, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_dtor(gquic_packet_handler_map_t *const handler) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    gquic_str_reset(&handler->stateless_reset_key);

    while (!gquic_rbtree_is_nil(handler->handlers)) {
        rbt = handler->handlers;
        gquic_rbtree_remove(&handler->handlers, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    while (!gquic_rbtree_is_nil(handler->reset_tokens)) {
        rbt = handler->reset_tokens;
        gquic_rbtree_remove(&handler->reset_tokens, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handler_map_listen(void *const handler_) {
    gquic_packet_buffer_t *buffer = NULL;
    gquic_packet_handler_map_t *handler = handler_;
    const void *recv_event = NULL;
    const liteco_channel_t *recv_chan = NULL;
    int recv_len = 0;
    char addr[sizeof(struct sockaddr_in6) > sizeof(struct sockaddr_in) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)] = { 0 };
    socklen_t addr_len = sizeof(addr);
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    for ( ;; ) {
        GQUIC_COGLOBAL_CHANNEL_RECV(exception, &recv_event, &recv_chan, 0, &handler->recv_event_chan, &handler->close_chan);
        GQUIC_LOG(GQUIC_LOG_DEBUG, "packet_handler_map recevied event");

        if (recv_chan == &handler->close_chan) {
            GQUIC_LOG(GQUIC_LOG_WARN, "packet_handler_map closed");
            break;
        }

        for ( ;; ) {
            if (GQUIC_ASSERT(gquic_packet_buffer_get(&buffer))) {
                goto finished;
            }
            if ((recv_len = recvfrom(handler->conn_fd,
                                     GQUIC_STR_VAL(&buffer->slice), GQUIC_STR_SIZE(&buffer->slice), 0, (struct sockaddr *) addr, &addr_len)) <= 0) {

                if (recv_len == -1 && errno == EAGAIN) {
                    GQUIC_ASSERT(gquic_packet_buffer_put(buffer));
                    break;
                }
                gquic_packet_handler_map_listen_close(handler, -1002);
                goto finished;
            }

            gquic_received_packet_t *recv_packet;
            if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&recv_packet, gquic_received_packet_t))) {
                goto finished;
            }
            gquic_received_packet_init(recv_packet);
            recv_packet->buffer = buffer;
            recv_packet->data.size = recv_len;
            recv_packet->data.val = GQUIC_STR_VAL(&buffer->slice);
            recv_packet->recv_time = gquic_time_now();
            if (addr_len == sizeof(struct sockaddr_in6)) {
                recv_packet->remote_addr.type = AF_INET6;
                recv_packet->remote_addr.addr.v6 = *(struct sockaddr_in6 *) addr;
            }
            else {
                recv_packet->remote_addr.type = AF_INET;
                recv_packet->remote_addr.addr.v4 = *(struct sockaddr_in *) addr;
            }

            gquic_packet_handler_map_handle_packet(handler, recv_packet);
        }
    }

finished:
    liteco_channel_close(&handler->listen_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_handle_packet(gquic_packet_handler_map_t *const handler, gquic_received_packet_t *const recv_packet) {
    const gquic_rbtree_t *rbt = NULL;
    __send_stateless_reset_param_t *param = NULL;
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (handler == NULL || recv_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_packet_header_deserialize_conn_id(&recv_packet->dst_conn_id, &recv_packet->data, handler->conn_id_len))) {
        gquic_packet_buffer_put(recv_packet->buffer);
        gquic_free(recv_packet);
        GQUIC_PROCESS_DONE(exception);
    } 

    GQUIC_LOG(GQUIC_LOG_INFO, "packet_handler_map handle packet");

    pthread_mutex_lock(&handler->mtx);
    do {
        // stateless reset 处理
        if (gquic_packet_handler_map_try_handle_stateless_reset(handler, &recv_packet->data)) {
            GQUIC_LOG(GQUIC_LOG_INFO, "packet_handler_map handle stateless reset");
            gquic_packet_buffer_put(recv_packet->buffer);
            gquic_free(recv_packet);
            break;
        }

        // 根据目的connection id找到数据包处理模块
        if (gquic_rbtree_find_cmp(&rbt, handler->handlers, &recv_packet->dst_conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
            GQUIC_LOG(GQUIC_LOG_INFO, "packet_handler_map use dst_conn_id find packet handler");

            GQUIC_PACKET_HANDLER_HANDLE_PACKET(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt), recv_packet);
            break;
        }

        // 如果不是长首部数据包并且并未找到对应目的connection id数据包处理模块，则应发送stateless reset消息给对端
        if ((GQUIC_STR_FIRST_BYTE(&recv_packet->data) & 0x80) == 0x00) {
            GQUIC_LOG(GQUIC_LOG_INFO, "packet_handler_map handle send stateless reset");

            if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&param, __send_stateless_reset_param_t))) {
                gquic_packet_buffer_put(recv_packet->buffer);
                gquic_free(recv_packet);
                GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_ALLOCATION_FAILED);
                break;
            }
            param->handler = handler;
            param->recv_packet = recv_packet;
            if (GQUIC_ASSERT(gquic_coglobal_execute(gquic_packet_handler_map_try_send_stateless_reset_co, param))) {
                gquic_packet_buffer_put(recv_packet->buffer);
                gquic_free(recv_packet);
                GQUIC_EXCEPTION_ASSIGN(exception, GQUIC_EXCEPTION_CREATE_THREAD_FAILED);
                break;
            }
            break;
        }

        // 判断为新的connection id
        if (handler->server != NULL) {
            GQUIC_LOG(GQUIC_LOG_INFO, "packet_handler_map use unknow_packet_handler handle packet");

            GQUIC_PACKET_UNKNOW_PACKET_HANDLER_HANDLE_PACKET(handler->server, recv_packet);
            break;
        }

        GQUIC_LOG(GQUIC_LOG_ERROR, "packet_handler_map done nothing");
    } while (0);
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static bool gquic_packet_handler_map_try_handle_stateless_reset(gquic_packet_handler_map_t *const handler, const gquic_str_t *const data) {
    const gquic_rbtree_t *rbt = NULL;
    __reset_token_param_t *param = NULL;
    if (handler == NULL || data == NULL) {
        return false;
    }
    if ((GQUIC_STR_FIRST_BYTE(data) & 0x80) != 0x00) {
        return false;
    }
    if (GQUIC_STR_SIZE(data) < 17) {
        return false;
    }
    gquic_str_t token = { 16, GQUIC_STR_VAL(data) - 16 };
    if (gquic_rbtree_find_cmp(&rbt, handler->reset_tokens, &token, gquic_packet_handler_rb_str_cmp) == 0) {
        if (GQUIC_ASSERT(GQUIC_MALLOC_STRUCT(&param, __reset_token_param_t))) {
            return false;
        }
        param->handler = *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt);
        param->err = -1001;
        if (GQUIC_ASSERT(gquic_coglobal_execute(gquic_packet_handler_map_reset_token_destroy_co, param))) {
            return false;
        }
        return true;
    }
    return false;
}

static gquic_exception_t gquic_packet_handler_map_try_send_stateless_reset_co(void *const param_) {
    __send_stateless_reset_param_t *param = param_;
    gquic_str_t token = { 0, NULL };
    gquic_str_t data = { 0, NULL };
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (!param->handler->stateless_reset_enabled) {
        goto finished;
    }
    if (GQUIC_STR_SIZE(&param->recv_packet->data) <= (1 + 20 + 4 + 1 + 16)) {
        goto finished;
    }
    if (GQUIC_ASSERT(gquic_packet_handler_map_get_stateless_reset_token(&token, param->handler, &param->recv_packet->dst_conn_id))) {
        goto finished;
    }
    if (GQUIC_ASSERT(gquic_str_alloc(&data, 1 + 20 + 4 + 1 + 16))) {
        goto finished;
    }
    RAND_bytes(GQUIC_STR_VAL(&data), GQUIC_STR_SIZE(&data) - 16);
    *(u_int8_t *) GQUIC_STR_VAL(&data) = (GQUIC_STR_FIRST_BYTE(&data) & 0x7f) | 0x40;
    memcpy(GQUIC_STR_VAL(&data) + GQUIC_STR_SIZE(&data) - GQUIC_STR_SIZE(&token), GQUIC_STR_VAL(&token), GQUIC_STR_SIZE(&token));
    if (param->recv_packet->remote_addr.type == AF_INET) {
        sendto(param->handler->conn_fd,
               GQUIC_STR_VAL(&data),
               GQUIC_STR_SIZE(&data),
               0,
               (struct sockaddr *) &param->recv_packet->remote_addr.addr.v4,
               sizeof(struct sockaddr_in));
    }
    else {
        sendto(param->handler->conn_fd,
               GQUIC_STR_VAL(&data),
               GQUIC_STR_SIZE(&data),
               0,
               (struct sockaddr *) &param->recv_packet->remote_addr.addr.v6,
               sizeof(struct sockaddr_in6));
    }

finished:
    gquic_packet_buffer_put(param->recv_packet->buffer);
    gquic_free(param->recv_packet);
    gquic_free(param);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handler_rb_str_cmp(void *const a, void *const b) {
    return gquic_str_cmp(a, b);
}

static gquic_exception_t gquic_packet_handler_map_reset_token_destroy_co(void *const param_) {
    __reset_token_param_t *param = param_;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PACKET_HANDLER_DESTROY(param->handler, param->err);
    gquic_free(param);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_get_stateless_reset_token(gquic_str_t *const token,
                                                                     gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id) {
    u_int32_t size = 0;
    if (token == NULL || handler == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT(gquic_str_alloc(token, EVP_MD_size(EVP_sha256())))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    if (!handler->stateless_reset_enabled) {
        RAND_bytes(GQUIC_STR_VAL(token), 16);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (HMAC(EVP_sha256(),
             GQUIC_STR_VAL(&handler->stateless_reset_key), GQUIC_STR_SIZE(&handler->stateless_reset_key),
             GQUIC_STR_VAL(conn_id), GQUIC_STR_SIZE(conn_id),
             GQUIC_STR_VAL(token), &size) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HMAC_FAILED);
    }
    if (GQUIC_STR_SIZE(token) > 16) {
        token->size = 16;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_add(gquic_str_t *const token,
                                               gquic_packet_handler_map_t *const handler,
                                               const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        pthread_mutex_unlock(&handler->mtx);

        if (token != NULL) {
            GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_get_stateless_reset_token(token, handler, conn_id));
        }

        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        pthread_mutex_unlock(&handler->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    pthread_mutex_unlock(&handler->mtx);

    if (token != NULL) {
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_get_stateless_reset_token(token, handler, conn_id));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_packet_handler_map_add_if_not_taken(gquic_packet_handler_map_t *handler, const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        pthread_mutex_unlock(&handler->mtx);
        return false;
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        pthread_mutex_unlock(&handler->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    pthread_mutex_unlock(&handler->mtx);

    return true;
}

gquic_exception_t gquic_packet_handler_map_remove(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&handler->handlers, &rbt);

        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));                                    
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_retire(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id) {
    gquic_phm_retire_timeout_param_t *param = NULL;
    if (handler == NULL || conn_id == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&param, gquic_phm_retire_timeout_param_t));
    param->handler = handler;
    gquic_str_copy(&param->conn_id, conn_id);

    GQUIC_ASSERT_FAST_RETURN(gquic_coglobal_delay_execute(gquic_time_now() + handler->delete_retired_session_after, gquic_retire_timeout_cb, param));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_retire_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    gquic_phm_retire_timeout_param_t *param = param_;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    pthread_mutex_lock(&param->handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->handlers, &param->conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&param->handler->handlers, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    pthread_mutex_unlock(&param->handler->mtx);

    gquic_str_reset(&param->conn_id);
    gquic_free(param);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_replace_with_closed(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id, gquic_packet_handler_t *const ph) {
    __replace_with_closed_timeout_param_t *param = NULL;
    gquic_rbtree_t *rbt = NULL;
    gquic_exception_t exception = GQUIC_SUCCESS;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    }
    else if (!GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    }
    else {
        pthread_mutex_unlock(&handler->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    pthread_mutex_unlock(&handler->mtx);

    if (GQUIC_MALLOC_STRUCT(&param, __replace_with_closed_timeout_param_t)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_str_copy(&param->conn_id, conn_id);
    param->handler = handler;
    param->ph = ph;

    GQUIC_ASSERT_FAST_RETURN(gquic_coglobal_delay_execute(gquic_time_now() + handler->delete_retired_session_after,
                                                          gquic_replace_with_closed_timeout_cb, param));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_replace_with_closed_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    __replace_with_closed_timeout_param_t *param = param_;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&param->handler->mtx);
    GQUIC_IO_CLOSE(&param->ph->closer);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->handlers, &param->conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&param->handler->handlers, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    pthread_mutex_unlock(&param->handler->mtx);

    gquic_str_reset(&param->conn_id);
    gquic_free(param);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_add_reset_token(gquic_packet_handler_map_t *const handler,
                                                           const gquic_str_t *const token, gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || token == NULL || ph == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->reset_tokens, (void *) token, gquic_packet_handler_rb_str_cmp) == 0) {
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        pthread_mutex_unlock(&handler->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        pthread_mutex_unlock(&handler->mtx);
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), token);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->reset_tokens, rbt, gquic_packet_handler_rb_str_cmp);
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_remove_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || token == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) token, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&handler->reset_tokens, &rbt);

        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));                                    
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_retire_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token) {
    __retire_reset_token_timeout_param_t *param = NULL;
    if (handler == NULL || token == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&param, __retire_reset_token_timeout_param_t));
    param->handler = handler;
    gquic_str_copy(&param->token, token);
    GQUIC_ASSERT_FAST_RETURN(gquic_coglobal_delay_execute(gquic_time_now() + handler->delete_retired_session_after,
                                                          gquic_retire_reset_token_timeout_cb, handler));
    

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_retire_reset_token_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    __retire_reset_token_timeout_param_t *param = param_;
    if (param == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&param->handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->reset_tokens, &param->token, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&param->handler->reset_tokens, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        gquic_free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    pthread_mutex_unlock(&param->handler->mtx);

    gquic_str_reset(&param->token);
    gquic_free(param);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_set_server(gquic_packet_handler_map_t *const handler, gquic_packet_unknow_packet_handler_t *const uph) {
    if (handler == NULL || uph == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    handler->server = uph;
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_close_server(gquic_packet_handler_map_t *const handler) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    handler->server = NULL;
    
    GQUIC_RBTREE_EACHOR_BEGIN(rbt, handler->handlers)
        if (!GQUIC_PACKET_HANDLER_IS_CLIENT(GQUIC_RBTREE_VALUE(rbt))) {
            GQUIC_IO_CLOSE(&(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt))->closer);
        }
    GQUIC_RBTREE_EACHOR_END(rbt)
    pthread_mutex_unlock(&handler->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_handler_map_close(gquic_packet_handler_map_t *const handler) {
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    close(handler->conn_fd);
    liteco_channel_close(&handler->listen_chan);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handler_map_listen_close(gquic_packet_handler_map_t *const handler, const gquic_exception_t err) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&handler->mtx);
    
    GQUIC_RBTREE_EACHOR_BEGIN(rbt, handler->handlers)
        GQUIC_PACKET_HANDLER_DESTROY(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt), err);
    GQUIC_RBTREE_EACHOR_END(rbt)
    if (handler->server != NULL) {
        GQUIC_PACKET_UNKNOW_PACKET_HANDLER_SET_CLOSE_ERR(handler->server, err);
    }
    handler->closed = 1;
    liteco_channel_close(&handler->close_chan);
    pthread_mutex_unlock(&handler->mtx);

    gquic_multiplexer_remove_conn(handler->conn_fd);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

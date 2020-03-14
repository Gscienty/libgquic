#include "packet/packet_handler_map.h"
#include "packet/handler.h"
#include "packet/multiplexer.h"
#include "net/conn.h"
#include "util/timeout.h"
#include "exception.h"
#include <sys/time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

typedef struct __send_stateless_reset_param_s __send_stateless_reset_param_t;
struct __send_stateless_reset_param_s {
    pthread_t thread;
    gquic_packet_handler_map_t *handler;
    gquic_received_packet_t *recv_packet;
};

typedef struct __reset_token_param_s __reset_token_param_t;
struct __reset_token_param_s {
    pthread_t thread;
    gquic_packet_handler_t *handler;
    int err;
};

typedef struct __retire_timeout_param_s __retire_timeout_param_t;
struct __retire_timeout_param_s {
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

static void *__packet_handler_map_listen(void *const);
static void *__packet_handler_map_try_send_stateless_reset(void *const);
static int gquic_packet_handler_map_try_handle_stateless_reset(gquic_packet_handler_map_t *const, const gquic_str_t *const);
static int gquic_packet_handler_rb_str_cmp(void *const, void *const);
static void *__packet_handler_map_reset_token_destory(void *const);
static int __retire_timeout_cb(void *const);
static int __replace_with_closed_timeout_cb(void *const);
static int __retire_reset_token_timeout_cb(void *const);
static int gquic_packet_handler_map_listen_close(gquic_packet_handler_map_t *const, const int);

int gquic_packet_unknow_packet_handler_init(gquic_packet_unknow_packet_handler_t *const handler) {
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    handler->handle_packet.cb = NULL;
    handler->handle_packet.self = NULL;
    handler->set_close_err.cb = NULL;
    handler->set_close_err.self = NULL;

    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_init(gquic_packet_handler_map_t *const handler) {
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_init(&handler->mtx, 0, 1);
    handler->conn_fd = 0;
    handler->conn_id_len = 0;
    gquic_rbtree_root_init(&handler->handlers);
    gquic_rbtree_root_init(&handler->reset_tokens);
    handler->server = NULL;

    sem_init(&handler->listening, 0, 0);
    handler->closed = 0;

    handler->delete_retired_session_after = 0;

    handler->stateless_reset_enabled = 0;
    gquic_str_init(&handler->stateless_reset_key);

    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_ctor(gquic_packet_handler_map_t *const handler,
                                  const int conn_fd,
                                  const int conn_id_len,
                                  const gquic_str_t *const stateless_reset_token) {
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    handler->conn_fd = conn_fd;
    handler->conn_id_len = conn_id_len;
    handler->delete_retired_session_after = 5 * 1000 * 1000;
    handler->stateless_reset_enabled = GQUIC_STR_SIZE(stateless_reset_token) > 0;
    gquic_str_copy(&handler->stateless_reset_key, stateless_reset_token);

    if (pthread_create(&handler->run_thread, NULL, __packet_handler_map_listen, handler) != 0) {
        return GQUIC_EXCEPTION_CREATE_THREAD_FAILED;
    }

    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_dtor(gquic_packet_handler_map_t *const handler) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_destroy(&handler->mtx);
    sem_destroy(&handler->listening);

    gquic_str_reset(&handler->stateless_reset_key);

    // TODO release unknow packet handler

    while (!gquic_rbtree_is_nil(handler->handlers)) {
        rbt = handler->handlers;
        gquic_rbtree_remove(&handler->handlers, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    while (!gquic_rbtree_is_nil(handler->reset_tokens)) {
        rbt = handler->reset_tokens;
        gquic_rbtree_remove(&handler->reset_tokens, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }

    return GQUIC_SUCCESS;
}

static void *__packet_handler_map_listen(void *const handler_) {
    gquic_packet_buffer_t *buffer = NULL;
    gquic_packet_handler_map_t *handler = handler_;
    ssize_t recv_len = 0;
    char addr[sizeof(struct sockaddr_in6) > sizeof(struct sockaddr_in) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)] = { 0 };
    socklen_t addr_len = 0;
    if (handler == NULL) {
        return NULL;
    }
    for ( ;; ) {
        addr_len = 0;
        if (GQUIC_ASSERT(gquic_packet_buffer_get(&buffer))) {
            break;
        }
        if ((recv_len = recvfrom(handler->conn_fd,
                                 GQUIC_STR_VAL(&buffer->slice),
                                 GQUIC_STR_SIZE(&buffer->slice),
                                 0,
                                 (struct sockaddr *) addr, &addr_len)) <= 0) {
            gquic_packet_handler_map_listen_close(handler, -1002);
            break;
        }
        gquic_received_packet_t *recv_packet;
        if ((recv_packet = malloc(sizeof(gquic_received_packet_t))) == NULL) {
            break;
        }
        gquic_received_packet_init(recv_packet);
        recv_packet->buffer = buffer;
        recv_packet->data.size = recv_len;
        recv_packet->data.val = GQUIC_STR_VAL(&buffer->slice);
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        recv_packet->recv_time = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
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
    sem_post(&handler->listening);
    return NULL;
}

int gquic_packet_handler_map_handle_packet(gquic_packet_handler_map_t *const handler, gquic_received_packet_t *const recv_packet) {
    const gquic_rbtree_t *rbt = NULL;
    __send_stateless_reset_param_t *param = NULL;
    int exception = GQUIC_SUCCESS;
    if (handler == NULL || recv_packet == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_ASSERT_CAUSE(exception,
                           gquic_packet_header_deserialize_conn_id(&recv_packet->dst_conn_id, &recv_packet->data, handler->conn_id_len))) {
        gquic_packet_buffer_put(recv_packet->buffer);
        free(recv_packet);
        return exception;
    }
    sem_wait(&handler->mtx);
    do {
        if (gquic_packet_handler_map_try_handle_stateless_reset(handler, &recv_packet->data)) {
            gquic_packet_buffer_put(recv_packet->buffer);
            free(recv_packet);
            break;
        }
        if (gquic_rbtree_find_cmp(&rbt, handler->handlers, &recv_packet->dst_conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
            GQUIC_PACKET_HANDLER_HANDLE_PACKET(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt), recv_packet);
            break;
        }
        if ((GQUIC_STR_FIRST_BYTE(&recv_packet->data) & 0x80) == 0x00) {
            if ((param = malloc(sizeof(__send_stateless_reset_param_t))) == NULL) {
                gquic_packet_buffer_put(recv_packet->buffer);
                free(recv_packet);
                exception = GQUIC_EXCEPTION_ALLOCATION_FAILED;
                break;
            }
            param->handler = handler;
            param->recv_packet = recv_packet;
            if (pthread_create(&param->thread, NULL, __packet_handler_map_try_send_stateless_reset, param) != 0) {
                gquic_packet_buffer_put(recv_packet->buffer);
                free(recv_packet);
                exception = GQUIC_EXCEPTION_CREATE_THREAD_FAILED;
                break;
            }
            break;
        }
        if (handler->server != NULL) {
            GQUIC_PACKET_UNKNOW_PACKET_HANDLER_HANDLE_PACKET(handler->server, recv_packet);
        }
    } while (0);
    sem_post(&handler->mtx);
    return exception;
}

static int gquic_packet_handler_map_try_handle_stateless_reset(gquic_packet_handler_map_t *const handler, const gquic_str_t *const data) {
    const gquic_rbtree_t *rbt = NULL;
    __reset_token_param_t *param = NULL;
    if (handler == NULL || data == NULL) {
        return 0;
    }
    if ((GQUIC_STR_FIRST_BYTE(data) & 0x80) != 0x00) {
        return 0;
    }
    if (GQUIC_STR_SIZE(data) < 17) {
        return 0;
    }
    gquic_str_t token = { 16, GQUIC_STR_VAL(data) - 16 };
    if (gquic_rbtree_find_cmp(&rbt, handler->reset_tokens, &token, gquic_packet_handler_rb_str_cmp) == 0) {
            if ((param = malloc(sizeof(__reset_token_param_t))) == NULL) {
                return 0;
            }
            param->handler = *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt);
            param->err = -1001;
            if (pthread_create(&param->thread, NULL, __packet_handler_map_reset_token_destory, param) != 0) {
                return 0;
            }
        return 1;
    }
    return 0;
}

static void *__packet_handler_map_try_send_stateless_reset(void *const param_) {
    __send_stateless_reset_param_t *param = param_;
    gquic_str_t token = { 0, NULL };
    gquic_str_t data = { 0, NULL };
    if (param == NULL) {
        return NULL;
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
    free(param->recv_packet);
    free(param);
    return NULL;
}

static int gquic_packet_handler_rb_str_cmp(void *const a, void *const b) {
    return gquic_str_cmp(a, b);
}

static void *__packet_handler_map_reset_token_destory(void *const param_) {
    __reset_token_param_t *param = param_;
    if (param == NULL) {
        return NULL;
    }
    GQUIC_PACKET_HANDLER_DESTROY(param->handler, param->err);
    free(param);
    return NULL;
}

int gquic_packet_handler_map_get_stateless_reset_token(gquic_str_t *const token,
                                                       gquic_packet_handler_map_t *const handler,
                                                       const gquic_str_t *const conn_id) {
    unsigned int size;
    if (token == NULL || handler == NULL || conn_id == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_ASSERT(gquic_str_alloc(token, EVP_MD_size(EVP_sha256())))) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    if (!handler->stateless_reset_enabled) {
        RAND_bytes(GQUIC_STR_VAL(token), 16);
        return GQUIC_SUCCESS;
    }
    if (HMAC(EVP_sha256(),
             GQUIC_STR_VAL(&handler->stateless_reset_key), GQUIC_STR_SIZE(&handler->stateless_reset_key),
             GQUIC_STR_VAL(conn_id), GQUIC_STR_SIZE(conn_id),
             GQUIC_STR_VAL(token), &size) <= 0) {
        return GQUIC_EXCEPTION_HMAC_FAILED;
    }
    if (GQUIC_STR_SIZE(token) > 16) {
        token->size = 16;
    }
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_add(gquic_str_t *const token,
                                 gquic_packet_handler_map_t *const handler,
                                 const gquic_str_t *const conn_id,
                                 gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        sem_post(&handler->mtx);
        return gquic_packet_handler_map_get_stateless_reset_token(token, handler, conn_id);
    }

    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        sem_post(&handler->mtx);
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    sem_post(&handler->mtx);

    return gquic_packet_handler_map_get_stateless_reset_token(token, handler, conn_id);
}

int gquic_packet_handler_map_add_if_not_taken(gquic_packet_handler_map_t *handler,
                                              const gquic_str_t *const conn_id,
                                              gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        return 0;
    }
    
    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        sem_post(&handler->mtx);
        return 0;
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        sem_post(&handler->mtx);
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    sem_post(&handler->mtx);

    return 1;
}

int gquic_packet_handler_map_remove(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || conn_id == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&handler->handlers, &rbt);

        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));                                    
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    sem_post(&handler->mtx);

    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_retire(gquic_packet_handler_map_t *const handler, const gquic_str_t *const conn_id) {
    __retire_timeout_param_t *param = NULL;
    if (handler == NULL || conn_id == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    if ((param = malloc(sizeof(__retire_timeout_param_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    param->handler = handler;
    gquic_str_copy(&param->conn_id, conn_id);
    gquic_timeout_start(handler->delete_retired_session_after, __retire_timeout_cb, param);

    return GQUIC_SUCCESS;
}

static int __retire_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    __retire_timeout_param_t *param = param_;
    if (param == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    sem_wait(&param->handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->handlers, &param->conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&rbt, &param->handler->handlers);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    sem_post(&param->handler->mtx);

    gquic_str_reset(&param->conn_id);
    free(param);

    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_replace_with_closed(gquic_packet_handler_map_t *const handler,
                                                 const gquic_str_t *const conn_id,
                                                 gquic_packet_handler_t *const ph) {
    __replace_with_closed_timeout_param_t *param = NULL;
    gquic_rbtree_t *rbt = NULL;
    int exception = GQUIC_SUCCESS;
    if (handler == NULL || conn_id == NULL || ph == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    }
    else if (!GQUIC_ASSERT_CAUSE(exception, gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        gquic_str_copy(GQUIC_RBTREE_KEY(rbt), conn_id);
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        gquic_rbtree_insert_cmp(&handler->handlers, rbt, gquic_packet_handler_rb_str_cmp);
    }
    else {
        sem_post(&handler->mtx);
        return exception;
    }
    sem_post(&handler->mtx);

    if ((param = malloc(sizeof(__replace_with_closed_timeout_param_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_copy(&param->conn_id, conn_id);
    param->handler = handler;
    param->ph = ph;
    gquic_timeout_start(handler->delete_retired_session_after, __replace_with_closed_timeout_cb, param);

    return GQUIC_SUCCESS;
}

static int __replace_with_closed_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    __replace_with_closed_timeout_param_t *param = param_;
    if (param == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&param->handler->mtx);
    GQUIC_IO_CLOSE(&param->ph->closer);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->handlers, &param->conn_id, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&param->handler->handlers, &rbt);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    sem_post(&param->handler->mtx);
    gquic_str_reset(&param->conn_id);
    free(param);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_add_reset_token(gquic_packet_handler_map_t *const handler,
                                             const gquic_str_t *const token,
                                             gquic_packet_handler_t *const ph) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || token == NULL || ph == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **)&rbt, handler->reset_tokens, (void *) token, gquic_packet_handler_rb_str_cmp) == 0) {
        *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
        sem_post(&handler->mtx);
        return GQUIC_SUCCESS;
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(gquic_str_t), sizeof(gquic_packet_handler_t *)))) {
        sem_post(&handler->mtx);
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    gquic_str_init(GQUIC_RBTREE_KEY(rbt));
    gquic_str_copy(GQUIC_RBTREE_KEY(rbt), token);
    *(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt) = ph;
    gquic_rbtree_insert_cmp(&handler->reset_tokens, rbt, gquic_packet_handler_rb_str_cmp);
    sem_post(&handler->mtx);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_remove_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token) {
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL || token == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, handler->handlers, (void *) token, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&handler->reset_tokens, &rbt);

        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));                                    
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    sem_post(&handler->mtx);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_retire_reset_token(gquic_packet_handler_map_t *const handler, const gquic_str_t *const token) {
    __retire_reset_token_timeout_param_t *param = NULL;
    if (handler == NULL || token == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((param = malloc(sizeof(__retire_reset_token_timeout_param_t))) == NULL) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    param->handler = handler;
    gquic_str_copy(&param->token, token);
    gquic_timeout_start(handler->delete_retired_session_after, __retire_reset_token_timeout_cb, param);
    return GQUIC_SUCCESS;
}

static int __retire_reset_token_timeout_cb(void *const param_) {
    gquic_rbtree_t *rbt = NULL;
    __retire_reset_token_timeout_param_t *param = param_;
    if (param == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&param->handler->mtx);
    if (gquic_rbtree_find_cmp((const gquic_rbtree_t **) &rbt, param->handler->reset_tokens, &param->token, gquic_packet_handler_rb_str_cmp) == 0) {
        gquic_rbtree_remove(&rbt, &param->handler->reset_tokens);
        gquic_str_reset(GQUIC_RBTREE_KEY(rbt));
        free(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt));
        gquic_rbtree_release(rbt, NULL);
    }
    sem_post(&param->handler->mtx);
    gquic_str_reset(&param->token);
    free(param);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_set_server(gquic_packet_handler_map_t *const handler, gquic_packet_unknow_packet_handler_t *const uph) {
    if (handler == NULL || uph == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&handler->mtx);
    handler->server = uph;
    sem_post(&handler->mtx);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_close_server(gquic_packet_handler_map_t *const handler) {
    gquic_list_t queue;
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_head_init(&queue);
    sem_wait(&handler->mtx);
    handler->server = NULL;
    // TODO handler->server release ?
    
    GQUIC_RBTREE_EACHOR_BEGIN(rbt, &queue, handler->handlers)
        if (!GQUIC_PACKET_HANDLER_IS_CLIENT(GQUIC_RBTREE_VALUE(rbt))) {
            GQUIC_IO_CLOSE(&(*(gquic_packet_handler_t **) GQUIC_RBTREE_VALUE(rbt))->closer);
        }
    GQUIC_RBTREE_EACHOR_END(rbt, &queue)

    sem_post(&handler->mtx);
    return GQUIC_SUCCESS;
}

int gquic_packet_handler_map_close(gquic_packet_handler_map_t *const handler) {
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    close(handler->conn_fd);
    sem_post(&handler->listening);

    return GQUIC_SUCCESS;
}

static int gquic_packet_handler_map_listen_close(gquic_packet_handler_map_t *const handler, const int err) {
    gquic_list_t queue;
    gquic_rbtree_t *rbt = NULL;
    if (handler == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_head_init(&queue);
    sem_wait(&handler->mtx);
    
    GQUIC_RBTREE_EACHOR_BEGIN(rbt, &queue, handler->handlers)
        GQUIC_PACKET_HANDLER_DESTROY(GQUIC_RBTREE_VALUE(rbt), err);
    GQUIC_RBTREE_EACHOR_END(rbt, &queue)
    if (handler->server != NULL) {
        GQUIC_PACKET_UNKNOW_PACKET_HANDLER_SET_CLOSE_ERR(handler->server, err);
    }
    handler->closed = 1;
    sem_post(&handler->mtx);

    gquic_multiplexer_remove_conn(handler->conn_fd);
    return GQUIC_SUCCESS;
}

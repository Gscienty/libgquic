#include "packet/multiplexer.h"
#include "packet/header.h"
#include "util/malloc.h"
#include "server.h"
#include "exception.h"
#include "global_schedule.h"
#include <openssl/rand.h>

static int gquic_server_implement_unknow_packet_handler(gquic_packet_unknow_packet_handler_t **const, gquic_server_t *const);
static int gquic_server_set_close_err_wrapper(void *const, const int);
static int gquic_server_handle_packet_wrapper(void *const, gquic_received_packet_t *const);
static int gquic_server_handle_packet_inner_co(gquic_coroutine_t *const, void *const);
static int gquic_server_handle_packet_initial(gquic_session_t **const, gquic_server_t *const, gquic_received_packet_t *const);
static int gquic_server_session_run_co(gquic_coroutine_t *const, void *const);
static int gquic_server_handle_new_session_co(gquic_coroutine_t *const, void *const);

typedef struct gquic_server_handle_packet_s gquic_server_handle_packet_t;
struct gquic_server_handle_packet_s {
    gquic_server_t *server;
    gquic_received_packet_t *received_packet;
};

typedef struct gquic_server_handle_new_session_s gquic_server_handle_new_session_t;
struct gquic_server_handle_new_session_s {
    gquic_server_t *server;
    gquic_session_t *session;
};

int gquic_server_init(gquic_server_t *const server) {
    if (server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    server->accept_early_sess = 0;
    server->closed = 0;
    server->err = 0;
    gquic_net_conn_init(&server->conn);
    server->config = NULL;
    server->packet_handlers = NULL;
    gquic_coroutine_chain_init(&server->err_chain);
    gquic_coroutine_chain_init(&server->sess_chain);
    gquic_coroutine_chain_init(&server->done_chain);
    server->sess_count = 0;

    pthread_mutex_init(&server->mtx, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_ctor(gquic_server_t *const server, int fd, gquic_net_addr_t *const addr, gquic_config_t *const config, const int accept_early) {
    gquic_packet_unknow_packet_handler_t *handler = NULL;
    if (server == NULL || addr == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    server->config = config;
    server->conn.addr = *addr;
    server->conn.fd = fd;
    server->accept_early_sess = accept_early;
    GQUIC_ASSERT_FAST_RETURN(gquic_multiplexer_add_conn(&server->packet_handlers, fd, config->conn_id_len, &config->stateless_reset_key));
    GQUIC_ASSERT_FAST_RETURN(gquic_server_implement_unknow_packet_handler(&handler, server));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_set_server(server->packet_handlers, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_accept(gquic_coroutine_t *const co, gquic_session_t **const session_storage, gquic_server_t *const server) {
    int exception = GQUIC_SUCCESS;
    void *recv = NULL;
    gquic_coroutine_chain_t *recv_chain = NULL;
    if (co == NULL || session_storage == NULL || server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_EXCEPTION_ASSIGN(exception, gquic_coroutine_chain_recv(&recv, &recv_chain, co, 1,
                                                                 &server->done_chain,
                                                                 &server->sess_chain,
                                                                 &server->err_chain,
                                                                 NULL));
    if (recv_chain == &server->done_chain) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    else if (recv_chain == &server->sess_chain) {
        *session_storage = recv;
        server->sess_count--;
    }
    else if (recv_chain == &server->err_chain) {
        GQUIC_PROCESS_DONE(server->err);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_close(gquic_coroutine_t *const co, gquic_server_t *const server) {
    int exception = GQUIC_SUCCESS;
    if (server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&server->mtx);
    if (server->closed) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_handler_map_close_server(co, server->packet_handlers))) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_handler_map_close(server->packet_handlers))) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    server->closed = 1;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_coroutine_chain_boradcast_close(&server->err_chain, gquic_get_global_schedule()))) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    pthread_mutex_unlock(&server->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_implement_unknow_packet_handler(gquic_packet_unknow_packet_handler_t **const result, gquic_server_t *const server) {
    if (result == NULL || server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(result, gquic_packet_unknow_packet_handler_t));
    (*result)->handle_packet.self = server;
    (*result)->handle_packet.cb = gquic_server_handle_packet_wrapper;
    (*result)->set_close_err.self = server;
    (*result)->set_close_err.cb = gquic_server_set_close_err_wrapper;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_set_close_err(gquic_server_t *const server, const int err) {
    if (server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&server->mtx);
    if (server->closed) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    server->closed = 1;
    server->err = err;
    pthread_mutex_unlock(&server->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_set_close_err_wrapper(void *const server, const int err) {
    return gquic_server_set_close_err(server, err);
}

int gquic_server_handle_packet(gquic_server_t *const server, gquic_received_packet_t *const rp) {
    gquic_coroutine_t *co = NULL;
    gquic_server_handle_packet_t *handle_packet = NULL;
    if (server == NULL || rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&handle_packet, gquic_server_handle_packet_t));
    handle_packet->received_packet = rp;
    handle_packet->server = server;
    GQUIC_ASSERT_FAST_RETURN(gquic_global_schedule_join(&co, 1024 * 1024, gquic_server_handle_packet_inner_co, handle_packet));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_packet_wrapper(void *const server, gquic_received_packet_t *const rp) {
    return gquic_server_handle_packet(server, rp);
}

static int gquic_server_handle_packet_inner_co(gquic_coroutine_t *const co, void *const handle_packet) {
    gquic_session_t *sess = NULL;
    if (co == NULL || handle_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_server_t *const server = ((gquic_server_handle_packet_t *) handle_packet)->server;
    gquic_received_packet_t *const rp = ((gquic_server_handle_packet_t *) handle_packet)->received_packet;

    if (GQUIC_STR_SIZE(&rp->data) < 1200) {
        gquic_packet_buffer_put(rp->buffer);
        free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (gquic_packet_header_deserlialize_type(&rp->data) != GQUIC_LONG_HEADER_INITIAL) {
        gquic_packet_buffer_put(rp->buffer);
        free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_server_handle_packet_initial(&sess, server, rp));
    if (sess == NULL){
        gquic_packet_buffer_put(rp->buffer);
        free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_packet_initial(gquic_session_t **const session_storage,
                                              gquic_server_t *const server, gquic_received_packet_t *const received_packet) {
    // TODO free
    gquic_str_t conn_id = { 0, NULL };
    gquic_str_t cli_dst_conn_id = { 0, NULL };
    gquic_str_t dst_conn_id = { 0, NULL };
    gquic_net_conn_t *remote_conn = NULL;
    gquic_coroutine_t *session_run_co = NULL;
    gquic_coroutine_t *handle_new_session_co = NULL;
    gquic_server_handle_new_session_t *handle_new_session = NULL;
    if (session_storage == NULL || server == NULL || received_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (server->sess_count >= 32) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_BUSY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&conn_id, server->config->conn_id_len));
    if (RAND_bytes(GQUIC_STR_VAL(&conn_id), GQUIC_STR_SIZE(&conn_id)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RANDOM_FAILED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_header_deserialize_conn_id(&cli_dst_conn_id, &received_packet->data, server->config->conn_id_len));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_header_deserialize_src_conn_id(&dst_conn_id, &received_packet->data));

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&remote_conn, gquic_net_conn_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_net_conn_init(remote_conn));
    remote_conn->addr = received_packet->remote_addr;
    remote_conn->fd = server->conn.fd;

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(session_storage, gquic_session_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_session_ctor(*session_storage, remote_conn, server->packet_handlers,
                                                NULL, &cli_dst_conn_id, &dst_conn_id, &conn_id, NULL, server->config, 0, 0));
    int added = gquic_packet_handler_map_add_if_not_taken(server->packet_handlers, &cli_dst_conn_id,
                                                          gquic_session_implement_packet_handler(*session_storage));
    if (!added) {
        free(*session_storage);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_add(NULL, server->packet_handlers, &conn_id,
                                                          gquic_session_implement_packet_handler(*session_storage)));
    GQUIC_ASSERT_FAST_RETURN(gquic_global_schedule_join(&session_run_co, 1024 * 1024, gquic_server_session_run_co, *session_storage));

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&handle_new_session, gquic_server_handle_new_session_t));
    handle_new_session->server = server;
    handle_new_session->session = *session_storage;
    GQUIC_ASSERT_FAST_RETURN(gquic_global_schedule_join(&handle_new_session_co, 1024 * 1024, gquic_server_handle_new_session_co, handle_new_session));

    gquic_session_handle_packet(*session_storage, received_packet);

    gquic_str_reset(&conn_id);
    gquic_str_reset(&cli_dst_conn_id);
    gquic_str_reset(&dst_conn_id);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_session_run_co(gquic_coroutine_t *const co, void *const sess) {
    if (co == NULL || sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_session_run(co, sess));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_new_session_co(gquic_coroutine_t *const co, void *const handle_new_session_) {
    gquic_server_handle_new_session_t *const handle_new_session = handle_new_session_;
    void *recv = NULL;
    gquic_coroutine_chain_t *recv_chain = NULL;
    if (co == NULL || handle_new_session == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coroutine_chain_recv(&recv, &recv_chain, co, 1,
                               &handle_new_session->session->handshake_completed_chain,
                               &handle_new_session->session->done_chain,
                               NULL);
    if (recv_chain == &handle_new_session->session->done_chain) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    handle_new_session->server->sess_count++;
    gquic_coroutine_chain_send(&handle_new_session->server->sess_chain, gquic_get_global_schedule(), handle_new_session->session);
    free(handle_new_session);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

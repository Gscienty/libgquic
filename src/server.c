#include "packet/multiplexer.h"
#include "packet/header.h"
#include "util/malloc.h"
#include "server.h"
#include "exception.h"
#include "coglobal.h"
#include <openssl/rand.h>
#include <fcntl.h>

static int gquic_server_accept_inner_co(void *const);
static int gquic_server_implement_unknow_packet_handler(gquic_packet_unknow_packet_handler_t **const, gquic_server_t *const);
static int gquic_server_set_close_err_wrapper(void *const, const int);
static int gquic_server_handle_packet_wrapper(void *const, gquic_received_packet_t *const);
static int gquic_server_handle_packet_inner_co(void *const);
static int gquic_server_handle_packet_initial(gquic_session_t **const, gquic_server_t *const, gquic_received_packet_t *const);
static int gquic_server_session_run_co(void *const);
static int gquic_server_handle_new_session_co(void *const);

typedef struct gquic_server_handle_packet_s gquic_server_handle_packet_t;
struct gquic_server_handle_packet_s {
    gquic_server_t *server;
    gquic_received_packet_t *received_packet;
};

typedef struct gquic_server_accept_s gquic_server_accept_t;
struct gquic_server_accept_s {
    gquic_server_t *server;
    gquic_session_t *session;
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
    liteco_channel_init(&server->err_chain);
    liteco_channel_init(&server->sess_chain);
    liteco_channel_init(&server->done_chain);
    server->sess_count = 0;

    pthread_mutex_init(&server->mtx, NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_ctor(gquic_server_t *const server, const gquic_net_addr_t listen_addr, gquic_config_t *const config, const int accept_early) {
    int fd = -1;
    int flag = 0;
    gquic_packet_unknow_packet_handler_t *handler = NULL;
    if (server == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOC_SOCKET_FAILED);
    }
    if (listen_addr.type == AF_INET) {
        bind(fd, (struct sockaddr *) &listen_addr.addr.v4, sizeof(struct sockaddr_in));
    }
    else {
        bind(fd, (struct sockaddr *) &listen_addr.addr.v6, sizeof(struct sockaddr_in6));
    }
    flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);

    gquic_coglobal_thread_init(0);

    server->config = config;
    server->conn.addr = listen_addr;
    server->conn.fd = fd;
    server->accept_early_sess = accept_early;
    GQUIC_ASSERT_FAST_RETURN(gquic_multiplexer_add_conn(&server->packet_handlers, fd, config->conn_id_len, &config->stateless_reset_key));
    GQUIC_ASSERT_FAST_RETURN(gquic_server_implement_unknow_packet_handler(&handler, server));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_set_server(server->packet_handlers, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_accept(gquic_session_t **const session_storage, gquic_server_t *const server) {
    gquic_server_accept_t param;
    liteco_coroutine_t *co = NULL;
    if (session_storage == NULL || server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    param.server = server;
    param.session = NULL;
    gquic_coglobal_currmachine_execute(&co, gquic_server_accept_inner_co, &param);
    GQUIC_ASSERT_FAST_RETURN(gquic_coglobal_schedule_until_completed(co));

    *session_storage = param.session;
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_server_close(gquic_server_t *const server) {
    int exception = GQUIC_SUCCESS;
    if (server == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&server->mtx);
    if (server->closed) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_handler_map_close_server(server->packet_handlers))) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_packet_handler_map_close(server->packet_handlers))) {
        pthread_mutex_unlock(&server->mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    server->closed = 1;
    liteco_channel_close(&server->err_chain);
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
    gquic_server_handle_packet_t *handle_packet = NULL;
    if (server == NULL || rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "server handle packet (unknow_handler)");

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&handle_packet, gquic_server_handle_packet_t));
    handle_packet->received_packet = rp;
    handle_packet->server = server;
    gquic_coglobal_execute(gquic_server_handle_packet_inner_co, handle_packet);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_packet_wrapper(void *const server, gquic_received_packet_t *const rp) {
    return gquic_server_handle_packet(server, rp);
}

static int gquic_server_handle_packet_inner_co(void *const handle_packet) {
    gquic_session_t *sess = NULL;
    if (handle_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "server start handle packet");

    gquic_server_t *const server = ((gquic_server_handle_packet_t *) handle_packet)->server;
    gquic_received_packet_t *const rp = ((gquic_server_handle_packet_t *) handle_packet)->received_packet;

    if (GQUIC_STR_SIZE(&rp->data) < 1200) {
        gquic_packet_buffer_put(rp->buffer);
        gquic_free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    if (gquic_packet_header_deserlialize_type(&rp->data) != GQUIC_LONG_HEADER_INITIAL) {
        gquic_packet_buffer_put(rp->buffer);
        gquic_free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_server_handle_packet_initial(&sess, server, rp));
    if (sess == NULL){
        gquic_packet_buffer_put(rp->buffer);
        gquic_free(rp);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_packet_initial(gquic_session_t **const session_storage,
                                              gquic_server_t *const server, gquic_received_packet_t *const received_packet) {
    // TODO free
    gquic_str_t conn_id = { 0, NULL };
    gquic_str_t cli_dst_conn_id = { 0, NULL };
    gquic_str_t cli_src_conn_id = { 0, NULL };
    gquic_net_conn_t *remote_conn = NULL;
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
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_header_deserialize_src_conn_id(&cli_src_conn_id, &received_packet->data));

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&remote_conn, gquic_net_conn_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_net_conn_init(remote_conn));
    remote_conn->addr = received_packet->remote_addr;
    remote_conn->fd = server->conn.fd;

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(session_storage, gquic_session_t));
    GQUIC_ASSERT_FAST_RETURN(gquic_session_init(*session_storage));
    GQUIC_ASSERT_FAST_RETURN(gquic_session_ctor(*session_storage, remote_conn, server->packet_handlers,
                                                NULL, &cli_dst_conn_id, &cli_src_conn_id, &conn_id, NULL, server->config, 0, 0));
    bool added = gquic_packet_handler_map_add_if_not_taken(server->packet_handlers, &cli_dst_conn_id,
                                                          gquic_session_implement_packet_handler(*session_storage));
    if (!added) {
        gquic_free(*session_storage);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_LOG(GQUIC_LOG_INFO, "server packet_handler_map add new session");
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_add(NULL, server->packet_handlers, &conn_id,
                                                          gquic_session_implement_packet_handler(*session_storage)));
    gquic_coglobal_execute(gquic_server_session_run_co, *session_storage);

    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&handle_new_session, gquic_server_handle_new_session_t));
    handle_new_session->server = server;
    handle_new_session->session = *session_storage;
    gquic_coglobal_execute(gquic_server_handle_new_session_co, handle_new_session);

    gquic_session_handle_packet(*session_storage, received_packet);

    gquic_str_reset(&conn_id);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_session_run_co(void *const sess) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_session_run(sess));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_handle_new_session_co(void *const handle_new_session_) {
    gquic_server_handle_new_session_t *const handle_new_session = handle_new_session_;
    const void *recv = NULL;
    const liteco_channel_t *recv_chan = NULL;
    int exception = GQUIC_SUCCESS;
    if (handle_new_session == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_COGLOBAL_CHANNEL_RECV(exception, &recv, &recv_chan, 0,
                                &handle_new_session->session->handshake_completed_chain,
                                &handle_new_session->session->done_chain);
    if (recv_chan == &handle_new_session->session->done_chain) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    handle_new_session->server->sess_count++;
    liteco_channel_send(&handle_new_session->server->sess_chain, handle_new_session->session);
    gquic_free(handle_new_session);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_server_accept_inner_co(void *const param_) {
    gquic_server_accept_t *const param = param_;
    const void *recv = NULL;
    const liteco_channel_t *recv_chan = NULL;
    int exception = GQUIC_SUCCESS;
    if (param_ == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_COGLOBAL_CHANNEL_RECV(exception, &recv, &recv_chan, 0,
                                &param->server->done_chain,
                                &param->server->sess_chain,
                                &param->server->err_chain);
    if (recv_chan == &param->server->done_chain) {
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    else if (recv_chan == &param->server->sess_chain) {
        param->session = (gquic_session_t *) recv;
        param->server->sess_count--;
    }
    else if (recv_chan == &param->server->err_chain) {
        GQUIC_PROCESS_DONE(param->server->err);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

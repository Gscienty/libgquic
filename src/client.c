#include "packet/multiplexer.h"
#include "util/malloc.h"
#include "client.h"
#include "exception.h"
#include "coglobal.h"
#include <openssl/rand.h>
#include <fcntl.h>

static int gquic_client_on_handshake_completed(void *const);
static int gquic_client_session_run_co(void *const);
static int gquic_client_implement_packet_handler(gquic_packet_handler_t **const, gquic_client_t *const);
static int gquic_client_ctor(gquic_client_t *const, int, const gquic_net_addr_t *const, gquic_config_t *const);
static int gquic_client_handle_packet(gquic_client_t *const, gquic_received_packet_t *const);
static int gquic_client_create_sess(gquic_client_t *const);
static int gquic_client_establish_sec_conn(void *const);
static int gquic_client_connect(gquic_client_t *const);
static int gquic_client_waiting_acked_all_co(void *const);

static int gquic_client_handle_packet_wrapper(void *const, gquic_received_packet_t *const);
static int gquic_client_close_wrapper(void *const);
static int gquic_client_destroy_wrapper(void *const, const int);

int gquic_client_init(gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_net_conn_init(&client->conn);
    client->packet_handlers = NULL;
    client->config = NULL;
    gquic_str_init(&client->src_conn_id);
    gquic_str_init(&client->dst_conn_id);
    client->initial_pn = 0;
    client->sess_created = 0;
    gquic_session_init(&client->sess);
    liteco_channel_init(&client->err_chain);
    liteco_channel_init(&client->handshake_complete_chain);
    liteco_channel_init(&client->done_chain);

    pthread_mutex_init(&client->mtx, NULL);

    client->connected = ATOMIC_VAR_INIT(0);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_ctor(gquic_client_t *const client, int fd, const gquic_net_addr_t *const server_addr, gquic_config_t *const config) {
    u_int8_t rand = 0;
    int len = 0;
    if (client == NULL || server_addr == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&client->src_conn_id, config->conn_id_len));
    if (RAND_bytes(GQUIC_STR_VAL(&client->src_conn_id), GQUIC_STR_SIZE(&client->src_conn_id)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RANDOM_FAILED);
    }
    if (RAND_bytes(&rand, 1) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RANDOM_FAILED);
    }
    len = 8 + rand % 11;
    GQUIC_ASSERT_FAST_RETURN(gquic_str_alloc(&client->dst_conn_id, len));
    if (RAND_bytes(GQUIC_STR_VAL(&client->dst_conn_id), GQUIC_STR_SIZE(&client->dst_conn_id)) <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_RANDOM_FAILED);
    }
    client->conn.addr = *server_addr;
    client->conn.fd = fd;
    client->config = config;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_create(gquic_client_t *const client,
                        const gquic_net_addr_t client_addr, const gquic_net_addr_t server_addr, gquic_config_t *const config) {
    int fd = -1;
    int flag = 0;
    if (client == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((fd = socket(client_addr.type, SOCK_DGRAM, 0)) == -1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOC_SOCKET_FAILED);
    }
    if (client_addr.type == AF_INET) {
        bind(fd, (struct sockaddr *) &client_addr.addr.v4, sizeof(struct sockaddr_in));
    }
    else {
        bind(fd, (struct sockaddr *) &client_addr.addr.v6, sizeof(struct sockaddr_in6));
    }
    flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);

    gquic_coglobal_thread_init(0);

    GQUIC_ASSERT_FAST_RETURN(gquic_client_ctor(client, fd, &server_addr, config));
    GQUIC_ASSERT_FAST_RETURN(gquic_multiplexer_add_conn(&client->packet_handlers, fd, config->conn_id_len, &config->stateless_reset_key));
    GQUIC_ASSERT_FAST_RETURN(gquic_client_connect(client));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_establish_sec_conn(void *const client) {
    int exception = GQUIC_SUCCESS;
    const void *recv_event = NULL;
    const liteco_channel_t *recv_chan = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_coglobal_execute(gquic_client_session_run_co, client);

    GQUIC_COGLOBAL_CHANNEL_RECV(exception, &recv_event, &recv_chan, 0,
                                &((gquic_client_t *) client)->done_chain,
                                &((gquic_client_t *) client)->err_chain,
                                &((gquic_client_t *) client)->handshake_complete_chain);
    if (recv_chan == &((gquic_client_t *) client)->done_chain) {
        GQUIC_LOG(GQUIC_LOG_INFO, "client done");

        ((gquic_client_t *) client)->connected++;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    else if (recv_chan == &((gquic_client_t *) client)->err_chain) {
        GQUIC_LOG(GQUIC_LOG_INFO, "client recv a error");

        exception = *(int *) recv_event;
        gquic_free((void *) recv_event);
        ((gquic_client_t *) client)->connected++;
        GQUIC_PROCESS_DONE(exception);
    }
    else if (recv_chan == &((gquic_client_t *) client)->handshake_complete_chain) {
        GQUIC_LOG(GQUIC_LOG_INFO, "client handshake completed");

        ((gquic_client_t *) client)->connected++;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    ((gquic_client_t *) client)->connected++;
    GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
}

static int gquic_client_session_run_co(void *const client_){
    int exception = GQUIC_SUCCESS;
    int *err = NULL;
    gquic_client_t *const client = client_;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_session_run(&client->sess))) {
        gquic_packet_handler_map_close(client->packet_handlers);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&err, int));
    *err = exception;
    liteco_channel_send(&client->err_chain, err);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_on_handshake_completed(void *const client_) {
    gquic_client_t *const client = client_;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_LOG(GQUIC_LOG_INFO, "client handshake completed");

    liteco_channel_close(&client->handshake_complete_chain);
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_done(gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    liteco_channel_close(&client->done_chain);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_close(gquic_client_t *const client) {
    int exception = GQUIC_SUCCESS;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&client->mtx);
    if (client->sess_created) {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_close(&client->sess));
    }
    pthread_mutex_unlock(&client->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_client_destory(gquic_client_t *const client, const int err) {
    int exception = GQUIC_SUCCESS;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&client->mtx);
    if (client->sess_created) {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_destroy(&client->sess, err));
    }
    pthread_mutex_unlock(&client->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_client_handle_packet(gquic_client_t *const client, gquic_received_packet_t *const recv_packet) {
    if (client == NULL || recv_packet == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_session_handle_packet(&client->sess, recv_packet));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_create_sess(gquic_client_t *const client) {
    gquic_packet_handler_t *handler = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&client->mtx);
    if (!GQUIC_ASSERT(gquic_session_ctor(&client->sess, &client->conn, client->packet_handlers,
                                         NULL, NULL, &client->dst_conn_id, &client->src_conn_id,
                                         NULL,
                                         client->config,
                                         client->initial_pn,
                                         1))) {
        client->sess_created = 1;
        client->sess.on_handshake_completed.self = client;
        client->sess.on_handshake_completed.cb = gquic_client_on_handshake_completed;
    }
    pthread_mutex_unlock(&client->mtx);

    GQUIC_ASSERT_FAST_RETURN(gquic_client_implement_packet_handler(&handler, client));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_add(NULL, client->packet_handlers, &client->src_conn_id, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_implement_packet_handler(gquic_packet_handler_t **const result, gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(result, gquic_packet_handler_t));
    (*result)->handle_packet.cb = gquic_client_handle_packet_wrapper;
    (*result)->handle_packet.self = client;
    (*result)->is_client = true;
    (*result)->closer.closer.cb = gquic_client_close_wrapper;
    (*result)->closer.closer.self = client;
    (*result)->destroy.cb = gquic_client_destroy_wrapper;
    (*result)->destroy.self = client;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_handle_packet_wrapper(void *const client, gquic_received_packet_t *const recv_packet) {
    return gquic_client_handle_packet(client, recv_packet);
}

static int gquic_client_close_wrapper(void *const client) {
    return gquic_client_close(client);
}

static int gquic_client_destroy_wrapper(void *const client, const int err) {
    return gquic_client_destory(client, err);
}

static int gquic_client_connect(gquic_client_t *const client) {
    liteco_coroutine_t *co = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_ASSERT_FAST_RETURN(gquic_client_create_sess(client));
    gquic_coglobal_currmachine_execute(&co, gquic_client_establish_sec_conn, client);
    GQUIC_PROCESS_DONE(gquic_coglobal_schedule_until_completed(co));
}

int gquic_client_accept_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_accept_uni_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_open_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_session_open_stream(stream_storage, &client->sess));
}

int gquic_client_open_stream_sync(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_session_open_stream_sync(stream_storage, &client->sess));
}

int gquic_client_open_uni_stream(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_session_open_uni_stream(stream_storage, &client->sess));
}

int gquic_client_open_uni_stream_sync(gquic_stream_t **const stream_storage, gquic_client_t *const client) {
    if (stream_storage == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(gquic_session_open_uni_stream_sync(stream_storage, &client->sess));
}

int gquic_client_waiting_acked_all(gquic_client_t *const client) {
    liteco_coroutine_t *co = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    gquic_coglobal_currmachine_execute(&co, gquic_client_waiting_acked_all_co, client);
    GQUIC_PROCESS_DONE(gquic_coglobal_schedule_until_completed(co));
}

static int gquic_client_waiting_acked_all_co(void *const client_) {
    gquic_client_t *const client = client_;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(gquic_session_waiting_acked_all(&client->sess));
}

#include "packet/multiplexer.h"
#include "coroutine/coroutine.h"
#include "client.h"
#include "exception.h"
#include <openssl/rand.h>

#define GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_CLOSE 0x01
#define GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_ERROR 0x02
#define GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_HANDSHAKE_COMPLETE 0x03

typedef struct gquic_client_sec_conn_event_s gquic_client_sec_conn_event_t;
struct gquic_client_sec_conn_event_s {
    u_int8_t type;
    int err;
};

static int gquic_client_on_handshake_completed(void *const);
static int __gquic_client_session_run_co(gquic_coroutine_t *const, void *const);
static int gquic_client_implement_packet_handler(gquic_packet_handler_t **const, gquic_client_t *const);
static int gquic_client_ctor(gquic_client_t *const, int, gquic_net_addr_t *const, gquic_config_t *const, const int);
static int gquic_client_handle_packet(gquic_client_t *const, gquic_received_packet_t *const);
static int gquic_client_create_sess(gquic_client_t *const);
static int gquic_client_establish_sec_conn(gquic_client_t *const);
static int gquic_client_connect(gquic_client_t *const);

static int gquic_client_handle_packet_wrapper(void *const, gquic_received_packet_t *const);
static int gquic_client_is_client_wrapper(void *const);
static int gquic_client_close_wrapper(gquic_coroutine_t *const, void *const);
static int gquic_client_destroy_wrapper(gquic_coroutine_t *const co, void *const, const int);

int gquic_client_init(gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_init(&client->mtx, 0, 1);
    gquic_net_conn_init(&client->conn);
    client->created_conn = 0;
    client->packet_handlers = NULL;
    client->config = NULL;
    gquic_str_init(&client->src_conn_id);
    gquic_str_init(&client->dst_conn_id);
    client->initial_pn = 0;
    client->sess_created = 0;
    gquic_session_init(&client->sess);
    gquic_sem_list_init(&client->sec_conn_events);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_ctor(gquic_client_t *const client, int fd, gquic_net_addr_t *const addr, gquic_config_t *const config, const int created) {
    u_int8_t rand = 0;
    int len = 0;
    if (client == NULL || config == NULL) {
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
    client->conn.addr = *addr;
    client->conn.fd = fd;
    client->config = config;
    client->created_conn = created;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_create(gquic_client_t *const client, int fd, gquic_net_addr_t *const addr, gquic_config_t *const config, const int created) {
    if (client == NULL || addr == NULL || config == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_client_ctor(client, fd, addr, config, created));
    GQUIC_ASSERT_FAST_RETURN(gquic_multiplexer_add_conn(&client->packet_handlers, fd, config->conn_id_len, &config->stateless_reset_key));
    GQUIC_ASSERT_FAST_RETURN(gquic_client_connect(client));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_establish_sec_conn(gquic_client_t *const client) {
    gquic_client_sec_conn_event_t *event = NULL;
    gquic_coroutine_t *co = NULL;
    int exception = GQUIC_SUCCESS;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    client->sess.on_handshake_completed.self = client;
    client->sess.on_handshake_completed.cb = gquic_client_on_handshake_completed;

    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_alloc(&co));
    GQUIC_ASSERT_FAST_RETURN(gquic_coroutine_ctor(co, 1024 * 1024, __gquic_client_session_run_co, client));
    
    GQUIC_ASSERT_FAST_RETURN(gquic_sem_list_pop((void **) &event, &client->sec_conn_events));
    switch (event->type) {
    case GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_CLOSE:
        // TODO
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_close(co, &client->sess));
        break;

    case GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_ERROR:
        GQUIC_EXCEPTION_ASSIGN(exception, event->err);
        break;

    case GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_HANDSHAKE_COMPLETE:
        break;
    }

    gquic_list_release(event);
    GQUIC_PROCESS_DONE(exception);
}

static int __gquic_client_session_run_co(gquic_coroutine_t *const co, void *const client_){
    int exception = GQUIC_SUCCESS;
    gquic_client_t *const client = client_;
    gquic_client_sec_conn_event_t *event = NULL;
    if (co == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT_CAUSE(exception, gquic_session_run(co, &client->sess))) {
        gquic_packet_handler_map_close(client->packet_handlers);
    }
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    // TODO
    /*if (GQUIC_ASSERT(gquic_list_alloc((void **) &event, sizeof(gquic_client_sec_conn_event_t)))) {*/
        /*return NULL;*/
    /*}*/
    /*event->type = GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_ERROR;*/
    /*event->err = exception;*/
    /*gquic_sem_list_push(&client->sec_conn_events, event);*/

    /*return NULL;*/
}

static int gquic_client_on_handshake_completed(void *const client_) {
    gquic_client_t *const client = client_;
    gquic_client_sec_conn_event_t *event = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &event, sizeof(gquic_client_sec_conn_event_t)));
    event->type = GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_HANDSHAKE_COMPLETE;
    GQUIC_ASSERT_FAST_RETURN(gquic_sem_list_push(&client->sec_conn_events, event));
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_done(gquic_client_t *const client) {
    gquic_client_sec_conn_event_t *event = NULL;
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &event, sizeof(gquic_client_sec_conn_event_t)));
    event->type = GQUIC_CLIENT_SEC_CONN_EVENT_TYPE_CLOSE;
    GQUIC_ASSERT_FAST_RETURN(gquic_sem_list_push(&client->sec_conn_events, event));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_client_close(gquic_coroutine_t *const co, gquic_client_t *const client) {
    int exception = GQUIC_SUCCESS;
    if (co == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&client->mtx);
    if (client->sess_created) {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_close(co, &client->sess));
    }
    sem_post(&client->mtx);

    GQUIC_PROCESS_DONE(exception);
}

int gquic_client_destory(gquic_coroutine_t *const co, gquic_client_t *const client, const int err) {
    int exception = GQUIC_SUCCESS;
    if (co == NULL || client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&client->mtx);
    if (client->sess_created) {
        GQUIC_EXCEPTION_ASSIGN(exception, gquic_session_destroy(co, &client->sess, err));
    }
    sem_post(&client->mtx);

    GQUIC_PROCESS_DONE(exception);
}

static int gquic_client_handle_packet(gquic_client_t *const client, gquic_received_packet_t *const recv_packet) {
    if (client == NULL) {
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
    sem_wait(&client->mtx);
    if (!GQUIC_ASSERT(gquic_session_ctor(&client->sess, &client->conn, client->packet_handlers,
                       NULL, NULL, &client->dst_conn_id, &client->src_conn_id,
                       NULL,
                       client->config,
                       client->initial_pn,
                       1))) {
        client->sess_created = 1;
    }
    sem_post(&client->mtx);

    GQUIC_ASSERT_FAST_RETURN(gquic_client_implement_packet_handler(&handler, client));
    GQUIC_ASSERT_FAST_RETURN(gquic_packet_handler_map_add(NULL, client->packet_handlers, &client->src_conn_id, handler));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_implement_packet_handler(gquic_packet_handler_t **const result, gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *result = malloc(sizeof(gquic_packet_handler_t));
    if (*result == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    (*result)->handle_packet.cb = gquic_client_handle_packet_wrapper;
    (*result)->handle_packet.self = client;
    (*result)->is_client.cb = gquic_client_is_client_wrapper;
    (*result)->is_client.self = client;
    (*result)->closer.closer.cb = gquic_client_close_wrapper;
    (*result)->closer.closer.self = client;
    (*result)->destroy.cb = gquic_client_destroy_wrapper;
    (*result)->destroy.self = client;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_client_handle_packet_wrapper(void *const client, gquic_received_packet_t *const recv_packet) {
    return gquic_client_handle_packet(client, recv_packet);
}

static int gquic_client_is_client_wrapper(void *const client) {
    (void) client;

    return 1;
}

static int gquic_client_close_wrapper(gquic_coroutine_t *const co, void *const client) {
    return gquic_client_close(co, client);
}

static int gquic_client_destroy_wrapper(gquic_coroutine_t *const co, void *const client, const int err) {
    return gquic_client_destory(co, client, err);
}

static int gquic_client_connect(gquic_client_t *const client) {
    if (client == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_client_create_sess(client));
    GQUIC_ASSERT_FAST_RETURN(gquic_client_establish_sec_conn(client));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

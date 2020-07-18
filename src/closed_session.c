#include "closed_session.h"
#include "util/sem_list.h"
#include "util/malloc.h"
#include "exception.h"
#include <semaphore.h>
#include <pthread.h>

typedef struct gquic_closed_local_session_s gquic_closed_local_session_t;
struct gquic_closed_local_session_s {
    gquic_net_conn_t *conn;
    gquic_str_t data;
    
    sem_t close_mtx;
    int close_flag;

    gquic_sem_list_t run_event_list;
    int counter;

    int is_client;

    pthread_t thread;
};

#define GQUIC_CLOSED_LOCAL_SESSION_EVENT_CLOSE 0x01
#define GQUIC_CLOSED_LOCAL_SESSION_EVENT_RECEIVED_PACKET 0x02

static int gquic_closed_remote_session_handle_packet(void *const, gquic_received_packet_t *const);
static int gquic_closed_remote_session_close(void *const);
static int gquic_closed_remote_session_destory(void *const, const int);

static int gquic_closed_local_session_handle_packet(void *const, gquic_received_packet_t *const);
static int gquic_closed_local_session_close(void *const);
static int gquic_closed_local_session_destory(void *const, const int);
static int gquic_closed_local_session_dtor(gquic_closed_local_session_t *const);

static void *gquic_closed_local_session_thread(void *const);

int gquic_closed_remote_session_client_alloc(gquic_packet_handler_t **const handler_storage) {
    if (handler_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(handler_storage, gquic_packet_handler_t));
    (*handler_storage)->closer.closer.cb = gquic_closed_remote_session_close;
    (*handler_storage)->closer.closer.self = (*handler_storage);
    (*handler_storage)->destroy.cb = gquic_closed_remote_session_destory;
    (*handler_storage)->destroy.self = (*handler_storage);
    (*handler_storage)->handle_packet.cb = gquic_closed_remote_session_handle_packet;
    (*handler_storage)->handle_packet.self = (*handler_storage);
    (*handler_storage)->is_client = true;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_closed_remote_session_server_alloc(gquic_packet_handler_t **const handler_storage) {
    if (handler_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(handler_storage, gquic_packet_handler_t));

    (*handler_storage)->closer.closer.cb = gquic_closed_remote_session_close;
    (*handler_storage)->closer.closer.self = (*handler_storage);
    (*handler_storage)->destroy.cb = gquic_closed_remote_session_destory;
    (*handler_storage)->destroy.self = (*handler_storage);
    (*handler_storage)->handle_packet.cb = gquic_closed_remote_session_handle_packet;
    (*handler_storage)->handle_packet.self = (*handler_storage);
    (*handler_storage)->is_client = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_closed_remote_session_handle_packet(void *const _, gquic_received_packet_t *const rp) {
    (void) _;
    if (rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_packet_buffer_put(rp->buffer);
    gquic_free(rp);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_closed_remote_session_close(void *const _) {
    (void) _;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_closed_remote_session_destory(void *const _, const int __) {
    (void) _;
    (void) __;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_closed_local_session_alloc(gquic_packet_handler_t **const handler_storage,
                                     gquic_net_conn_t *const conn, gquic_str_t *const conn_close_packet, const int is_client) {
    gquic_closed_local_session_t *sess = NULL;
    if (handler_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(&sess, gquic_closed_local_session_t));
    GQUIC_ASSERT_FAST_RETURN(GQUIC_MALLOC_STRUCT(handler_storage, gquic_packet_handler_t));
    sess->conn = conn;
    sess->close_flag = 0;
    gquic_str_copy(&sess->data, conn_close_packet);
    sem_init(&sess->close_mtx, 0, 1);
    sess->counter = 0;
    sess->is_client = is_client;
    gquic_sem_list_init(&sess->run_event_list);

    (*handler_storage)->closer.closer.cb = gquic_closed_local_session_close;
    (*handler_storage)->closer.closer.self = sess;
    (*handler_storage)->destroy.cb = gquic_closed_local_session_destory;
    (*handler_storage)->destroy.self = sess;
    (*handler_storage)->handle_packet.cb = gquic_closed_local_session_handle_packet;
    (*handler_storage)->handle_packet.self = sess;
    (*handler_storage)->is_client = sess->is_client;

    pthread_create(&sess->thread, NULL, gquic_closed_local_session_thread, sess);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_closed_local_session_close(void *const sess_) {
    return gquic_closed_local_session_destory(sess_, 0);
}

static int gquic_closed_local_session_destory(void *const sess_, const int _) {
    // TODO
    (void) _;
    int exception = GQUIC_SUCCESS;
    gquic_closed_local_session_t *const sess = sess_;
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    sem_wait(&sess->close_mtx);
    if (sess->close_flag) {
        sem_post(&sess->close_mtx);
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    sess->close_flag = 1;
    u_int8_t *event = NULL;
    if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &event, sizeof(u_int8_t)))) {
        sem_post(&sess->close_mtx);
        GQUIC_PROCESS_DONE(exception);
    }
    *event = GQUIC_CLOSED_LOCAL_SESSION_EVENT_CLOSE;
    sem_post(&sess->close_mtx);

    gquic_sem_list_push(&sess->run_event_list, event);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_closed_local_session_handle_packet(void *const sess_, gquic_received_packet_t *const rp) {
    gquic_closed_local_session_t *const sess = sess_;
    if (sess_  == NULL || rp == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    u_int8_t *event = NULL;
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &event, sizeof(u_int8_t)));
    *event = GQUIC_CLOSED_LOCAL_SESSION_EVENT_RECEIVED_PACKET;
    gquic_packet_buffer_put(rp->buffer);
    gquic_free(rp);
    gquic_sem_list_push(&sess->run_event_list, event);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static void *gquic_closed_local_session_thread(void *const sess_) {
    u_int8_t *event = NULL;
    int i = 0;
    gquic_closed_local_session_t *const sess = sess_;
    if (sess  == NULL) {
        return NULL;
    }

    for ( ;; ) {
loop_start:
        gquic_sem_list_pop((void **) &event, &sess->run_event_list);
        switch (*event) {
        case GQUIC_CLOSED_LOCAL_SESSION_EVENT_CLOSE:
            gquic_list_release(event);
            gquic_closed_local_session_dtor(sess);
            return NULL;
        case GQUIC_CLOSED_LOCAL_SESSION_EVENT_RECEIVED_PACKET:
            sess->counter++;
            for (i = sess->counter; i > 1; i = i / 2) {
                if (i % 2 != 0) {
                    goto loop_start;
                }
            }
            gquic_net_conn_write(sess->conn, &sess->data);
        }
    }

    return NULL;
}

static int gquic_closed_local_session_dtor(gquic_closed_local_session_t *const sess) {
    if (sess == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_str_reset(&sess->data);
    // TODO clear sem_list

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

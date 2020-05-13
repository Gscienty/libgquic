#ifndef _LIBGQUIC_EVENT_EPOLL_H
#define _LIBGQUIC_EVENT_EPOLL_H

#include <sys/epoll.h>

#define GQUIC_EVENT_EPOLL_CONNECTION_COUNT 8
#define GQUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT 8

typedef struct gquic_event_epoll_s gquic_event_epoll_t;
struct gquic_event_epoll_s {
    struct epoll_event actives[GQUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT];
    int ep;

    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } process_cb;
};

#define GQUIC_EVENT_EPOLL_PROCESS(event, obj) \
    ((event)->process_cb.self == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (event)->process_cb.cb((event)->process_cb.self, (obj)))

int gquic_event_epoll_init(gquic_event_epoll_t *const event);
int gquic_event_epoll_ctor(gquic_event_epoll_t *const event, void *const process_self, int (*process_cb) (void *const, void *const));
int gquic_event_epoll_dtor(gquic_event_epoll_t *const event);
int gquic_event_epoll_add(gquic_event_epoll_t *const event, int fd, void *const obj);
int gquic_event_epoll_remove(gquic_event_epoll_t *const event, int fd);
int gquic_event_epoll_process(gquic_event_epoll_t *const event, const u_int64_t timeout);

#endif

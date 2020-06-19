#include "event/epoll.h"
#include "exception.h"
#include "log.h"
#include <stddef.h>

int gquic_event_epoll_init(gquic_event_epoll_t *const event) {
    if (event == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    event->ep = -1;
    event->process_cb.cb = NULL;
    event->process_cb.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_event_epoll_ctor(gquic_event_epoll_t *const event, void *const process_self, int (*process_cb) (void *const, void *const)) {
    if (event == NULL || process_self == NULL || process_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    event->ep = epoll_create(GQUIC_EVENT_EPOLL_CONNECTION_COUNT);
    if (event->ep == -1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CREATE_EPOLL_FAILED);
    }
    event->process_cb.cb = process_cb;
    event->process_cb.self = process_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_event_epoll_dtor(gquic_event_epoll_t *const event) {
    if (event == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_event_epoll_add(gquic_event_epoll_t *const event, int fd, void *const obj) {
    struct epoll_event ee;
    if (event == NULL || obj == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ee.events = EPOLLIN | EPOLLET;
    ee.data.ptr = obj;

    if (epoll_ctl(event->ep, EPOLL_CTL_ADD, fd, &ee) == -1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_CONNECTION_ADD_EPOLL_FAILED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_event_epoll_process(gquic_event_epoll_t *const event, const u_int64_t timeout) {
    int active_events = 0;
    int i = 0;
    if (event == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    active_events = epoll_wait(event->ep, event->actives, GQUIC_EVENT_EPOLL_MAX_ACTIVES_COUNT, timeout);
    if (active_events == -1) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_EPOLL_WAIT_FAILED);
    }
    for (i = 0; i < active_events; i++) {
        GQUIC_ASSERT(GQUIC_EVENT_EPOLL_PROCESS(event, event->actives[i].data.ptr));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_event_epoll_remove(gquic_event_epoll_t *const event, int fd) {
    struct epoll_event ee;
    if (event == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    ee.data.ptr = NULL;
    ee.events = 0;
    epoll_ctl(event->ep, fd, EPOLL_CTL_DEL, &ee);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

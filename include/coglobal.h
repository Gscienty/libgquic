#ifndef _LIBGQUIC_COGLOBAL_H
#define _LIBGQUIC_COGLOBAL_H

#include "liteco.h"
#include "exception.h"

int gquic_coglobal_execute(int (*func) (void *const), void *const args);
int gquic_coglobal_currmachine_execute(liteco_coroutine_t **const co_storage, int (*func) (void *const), void *const args);
int gquic_coglobal_delay_execute(const u_int64_t timeout, int (*func) (void *const), void *const args);
int gquic_coglobal_channel_recv(const void **const event, const liteco_channel_t **const recv_channel,
                                liteco_channel_t *const *channels, const u_int64_t timeout);
int gquic_coglobal_schedule();
int gquic_coglobal_schedule_until_completed(const liteco_coroutine_t *const co);
int gquic_coglobal_thread_init(int ith);
int gquic_coglobal_yield();

#define GQUIC_COGLOBAL_CHANNEL_RECV(exception, event, recv_channel, timeout, ...) \
(({\
    liteco_channel_t *const recv_channels[] = { __VA_ARGS__, NULL }; \
    exception = gquic_coglobal_channel_recv(event, recv_channel, recv_channels, timeout); \
}), exception)

#endif

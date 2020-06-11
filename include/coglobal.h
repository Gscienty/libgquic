#ifndef _LIBGQUIC_COGLOBAL_H
#define _LIBGQUIC_COGLOBAL_H

#include "liteco.h"

int gquic_coglobal_execute(int (*func) (void *const), void *args);
int gquic_coglobal_channel_recv(const void **const event, const liteco_channel_t **const recv_channel,
                                liteco_channel_t *const *channels, const u_int64_t timeout);
int gquic_coglobal_schedule();
int gquic_coglobal_thread_init(int ith);

#define GQUIC_COGLOBAL_CHANNEL_RECV(event, recv_channel, timeout, ...) \
({\
    liteco_channel_t *const recv_channels[] = { __VA_ARGS__, NULL }; \
    gquic_coglobal_channel_recv(event, recv_channel, recv_channels, timeout); \
})

#endif

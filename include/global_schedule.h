#ifndef _LIBGQUIC_GLOBAL_SCHEDULE_H
#define _LIBGQUIC_GLOBAL_SCHEDULE_H

#include "coroutine/schedule.h"

gquic_coroutine_schedule_t *gquic_get_global_schedule();

int gquic_global_schedule_join(gquic_coroutine_t **const co_storage,
                               const size_t stack_len, int (*func) (gquic_coroutine_t *const, void *const), void *args);

int gquic_global_schedule_timeout_join(gquic_coroutine_t **const co_storage, const u_int64_t timeout,
                                       const size_t stack_len, int (*func) (gquic_coroutine_t *const, void *const), void *args);

#endif

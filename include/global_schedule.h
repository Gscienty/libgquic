#ifndef _LIBGQUIC_GLOBAL_SCHEDULE_H
#define _LIBGQUIC_GLOBAL_SCHEDULE_H

#include "coroutine/schedule.h"

gquic_coroutine_schedule_t *gquic_get_global_schedule();

#endif

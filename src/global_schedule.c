#include "global_schedule.h"
#include <pthread.h>

gquic_coroutine_schedule_t *gquic_get_global_schedule() {
    static gquic_coroutine_schedule_t sche;
    static int inited = 0;
    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mtx);
    if (inited == 0) {
        gquic_coroutine_schedule_init(&sche);
        inited = 1;
    }
    pthread_mutex_unlock(&mtx);

    return &sche;
}

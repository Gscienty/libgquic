#ifndef _LIBGQUIC_UTIL_SEM_LIST_H
#define _LIBGQUIC_UTIL_SEM_LIST_H

#include "util/list.h"
#include <semaphore.h>

#define GQUIC_SEM_LIST(h) (&((h)->list))

typedef struct gquic_sem_list_s gquic_sem_list_t;
struct gquic_sem_list_s {
    sem_t sem;
    sem_t mtx;
    gquic_list_t list;
};

int gquic_sem_list_init(gquic_sem_list_t *const list);
int gquic_sem_list_sem_release(gquic_sem_list_t *const list);

#endif

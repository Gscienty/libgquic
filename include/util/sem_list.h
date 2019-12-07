#ifndef _LIBGQUIC_UTIL_SEM_LIST_H
#define _LIBGQUIC_UTIL_SEM_LIST_H

#include "util/list.h"
#include <semaphore.h>

#define GQUIC_SEM_LIST(h) (&((h)->list))
#define GQUIC_SEM_LIST_FIRST(h) (GQUIC_LIST_FIRST(GQUIC_SEM_LIST((h))))
#define GQUIC_SEM_LIST_LOCK(h) (sem_wait(&((h)->mtx)))
#define GQUIC_SEM_LIST_UNLOCK(h) (sem_post(&((h)->mtx)))
#define GQUIC_SEM_LIST_WAIT(h) (sem_wait(&((h)->sem)))
#define GQUIC_SEM_LIST_NOTIFY(h) (sem_post(&((h)->sem)))

typedef struct gquic_sem_list_s gquic_sem_list_t;
struct gquic_sem_list_s {
    sem_t sem;
    sem_t mtx;
    gquic_list_t list;
};

int gquic_sem_list_init(gquic_sem_list_t *const list);
int gquic_sem_list_sem_release(gquic_sem_list_t *const list);

int gquic_sem_list_pop(void **const event, gquic_sem_list_t *const list);
int gquic_sem_list_waiting_pop(void **const event, gquic_sem_list_t *const list, int (*cmp)(const void *const, const void *const), const void *const arg);
int gquic_sem_list_push(gquic_sem_list_t *const list, void *const event);
int gquic_sem_list_rpush(gquic_sem_list_t *const list, void *const event);

#endif

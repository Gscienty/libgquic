#include "util/sem_list.h"

int gquic_sem_list_init(gquic_sem_list_t *const list) {
    if (list == NULL) {
        return -1;
    }
    gquic_list_head_init(&list->list);
    sem_init(&list->mtx, 0, 1);
    sem_init(&list->sem, 0, 0);
    return 0;
}

int gquic_sem_list_sem_release(gquic_sem_list_t *const list) {
    if (list == NULL) {
        return -1;
    }
    sem_destroy(&list->mtx);
    sem_destroy(&list->sem);

    return 0;
}

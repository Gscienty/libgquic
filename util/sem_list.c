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

int gquic_sem_list_pop(void **const event, gquic_sem_list_t *const list) {
    if (event == NULL || list == NULL) {
        return -1;
    }
    GQUIC_SEM_LIST_WAIT(list);
    GQUIC_SEM_LIST_LOCK(list);
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return -2;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return 0;
}

int gquic_sem_list_waiting_pop(void **const event, gquic_sem_list_t *const list, int (*cmp)(const void *const, const void *const), const void *const arg) {
    if (event == NULL || list == NULL || cmp == NULL) {
        return -1;
    }
init:
    GQUIC_SEM_LIST_WAIT(list);
    GQUIC_SEM_LIST_LOCK(list);
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return -2;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    if (cmp(event, arg) != 0) {
        *event = NULL;
        GQUIC_SEM_LIST_UNLOCK(list);
        GQUIC_SEM_LIST_NOTIFY(list);
        goto init;
    }
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return 0;
}

int gquic_sem_list_push(gquic_sem_list_t *const list, void *const event) {
    if (list == NULL || event == NULL) {
        return -1;
    }
    GQUIC_SEM_LIST_LOCK(list);
    gquic_list_insert_before(GQUIC_SEM_LIST(list), event);
    GQUIC_SEM_LIST_UNLOCK(list);
    GQUIC_SEM_LIST_NOTIFY(list);
    return 0;
}

int gquic_sem_list_rpush(gquic_sem_list_t *const list, void *const event) {
    if (list == NULL || event == NULL) {
        return -1;
    }
    GQUIC_SEM_LIST_LOCK(list);
    gquic_list_insert_after(GQUIC_SEM_LIST(list), event);
    GQUIC_SEM_LIST_UNLOCK(list);
    GQUIC_SEM_LIST_NOTIFY(list);
    return 0;
}

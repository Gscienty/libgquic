#include "util/sem_list.h"
#include "exception.h"

int gquic_sem_list_init(gquic_sem_list_t *const list) {
    if (list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    list->closed = 0;
    gquic_list_head_init(&list->list);
    sem_init(&list->mtx, 0, 1);
    sem_init(&list->sem, 0, 0);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_sem_dtor(gquic_sem_list_t *const list) {
    if (list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_destroy(&list->mtx);
    sem_destroy(&list->sem);

    return GQUIC_SUCCESS;
}

int gquic_sem_list_time_pop(void **const event, gquic_sem_list_t *const list, const u_int64_t deadline) {
    struct timespec spec;
    if (event == NULL || list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    spec.tv_sec = deadline / (1000 * 1000);
    spec.tv_nsec = deadline % (1000 * 1000) * 1000;
    if (GQUIC_SEM_LIST_TIME_WAIT(list, &spec) != 0) {
        return GQUIC_EXCEPTION_TIMEOUT;
    }
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_EMPTY;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_try_pop(void **const event, gquic_sem_list_t *const list) {
    if (event == NULL || list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_SEM_LIST_TRY_WAIT(list) != 0) {
        return GQUIC_EXCEPTION_ATTEMPT_FAILED;
    }
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_EMPTY;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_pop(void **const event, gquic_sem_list_t *const list) {
    if (event == NULL || list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_SEM_LIST_WAIT(list);
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_EMPTY;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_waiting_pop(void **const event, gquic_sem_list_t *const list, int (*cmp)(const void *const, const void *const), const void *const arg) {
    if (event == NULL || list == NULL || cmp == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
init:
    GQUIC_SEM_LIST_WAIT(list);
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    if (gquic_list_head_empty(GQUIC_SEM_LIST(list))) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_EMPTY;
    }
    *event = GQUIC_SEM_LIST_FIRST(list);
    if (cmp(*event, arg) != 0) {
        *event = NULL;
        GQUIC_SEM_LIST_UNLOCK(list);
        GQUIC_SEM_LIST_NOTIFY(list);
        goto init;
    }
    gquic_list_remove(*event);
    GQUIC_SEM_LIST_UNLOCK(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_push(gquic_sem_list_t *const list, void *const event) {
    if (list == NULL || event == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    gquic_list_insert_before(GQUIC_SEM_LIST(list), event);
    GQUIC_SEM_LIST_UNLOCK(list);
    GQUIC_SEM_LIST_NOTIFY(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_rpush(gquic_sem_list_t *const list, void *const event) {
    if (list == NULL || event == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_SEM_LIST_LOCK(list);
    if (list->closed) {
        GQUIC_SEM_LIST_UNLOCK(list);
        return GQUIC_EXCEPTION_CLOSED;
    }
    gquic_list_insert_after(GQUIC_SEM_LIST(list), event);
    GQUIC_SEM_LIST_UNLOCK(list);
    GQUIC_SEM_LIST_NOTIFY(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_list_close(gquic_sem_list_t *const list) {
    if (list == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    GQUIC_SEM_LIST_LOCK(list);
    list->closed = 1;
    GQUIC_SEM_LIST_UNLOCK(list);
    GQUIC_SEM_LIST_NOTIFY(list);
    return GQUIC_SUCCESS;
}

int gquic_sem_lise_closed(gquic_sem_list_t *const list) {
    int ret;
    if (list == NULL) {
        return 1;
    }
    GQUIC_SEM_LIST_LOCK(list);
    ret = list->closed;
    GQUIC_SEM_LIST_UNLOCK(list);
    return ret;
}

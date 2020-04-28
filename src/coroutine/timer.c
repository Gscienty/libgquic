#include "coroutine/timer.h"
#include "exception.h"

int gquic_coroutine_timer_init(gquic_coroutine_timer_t *const timer) {
    if (timer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&timer->waiting);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_timer_push(gquic_coroutine_timer_t *const timer, gquic_coroutine_t *const co, const u_int64_t timeout) {
    int inserted = 0;
    gquic_coroutine_timer_unit_t *eachor_unit = NULL;
    gquic_coroutine_timer_unit_t *unit = NULL;
    if (timer == NULL || co == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &unit, sizeof(gquic_coroutine_timer_unit_t)));
    unit->co = co;
    unit->timeout = timeout;

    GQUIC_LIST_FOREACH(eachor_unit, &timer->waiting) {
        if (unit->timeout < eachor_unit->timeout) {
            inserted = 1;
            gquic_coroutine_join_ref(co);
            gquic_list_insert_before(&GQUIC_LIST_META(eachor_unit), unit);
            break;
        }
    }
    if (!inserted) {
        gquic_coroutine_join_ref(co);
        gquic_list_insert_before(&timer->waiting, unit);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_coroutine_timer_pop(gquic_coroutine_t **const co_storage, gquic_coroutine_timer_t *const timer) {
    if (co_storage == NULL || timer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_coroutine_timer_empty(timer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_EMPTY);
    }
    *co_storage = ((gquic_coroutine_timer_unit_t *) GQUIC_LIST_FIRST(&timer->waiting))->co;
    gquic_list_release(GQUIC_LIST_FIRST(&timer->waiting));
    gquic_coroutine_join_unref(*co_storage);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int64_t gquic_coroutine_timer_late(gquic_coroutine_timer_t *const timer) {
    if (timer == NULL) {
        return 0;
    }
    if (gquic_list_head_empty(&timer->waiting)) {
        return 0;
    }
    return ((gquic_coroutine_timer_unit_t *) GQUIC_LIST_FIRST(&timer->waiting))->timeout;
}

int gquic_coroutine_timer_exist(gquic_coroutine_timer_t *const timer, const gquic_coroutine_t *const co) {
    gquic_coroutine_timer_unit_t *unit = NULL;
    if (timer == NULL || co == NULL) {
        return 0;
    }
    GQUIC_LIST_FOREACH(unit, &timer->waiting) {
        if (unit->co == co) {
            return 1;
        }
    }

    return 0;
}

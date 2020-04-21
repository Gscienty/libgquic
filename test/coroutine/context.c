#include "unit_test.h"
#include "coroutine/schedule.h"
#include "coroutine/coroutine.h"
#include "util/str.h"
#include <string.h>

gquic_couroutine_context_t main_ctx;
gquic_couroutine_context_t child_ctx;

int maked_fn(gquic_coroutine_t *co, void *const _) {
    (void) _;
    printf("HERE\n");
    gquic_coroutine_yield(co);
    printf("HERE3\n");

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(schedule_remain) {
    gquic_coroutine_schedule_t sche;
    gquic_coroutine_schedule_init(&sche);

    gquic_coroutine_t *co;
    gquic_coroutine_alloc(&co);
    gquic_coroutine_ctor(co, 4096, maked_fn, NULL);

    gquic_coroutine_schedule_join(&sche, co);

    gquic_coroutine_schedule_resume(&sche);

    printf("HERE2\n");

    gquic_coroutine_schedule_resume(&sche);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

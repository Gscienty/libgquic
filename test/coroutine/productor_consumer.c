#include "coroutine/schedule.h"
#include "coroutine/chain.h"
#include "unit_test.h"
#include <malloc.h>
#include <stdio.h>

int productor_co_func(gquic_coroutine_t *const co, void *const chain) {
    for ( ;; ) {
        int *product;
        gquic_coroutine_chain_recv((void **) &product, co, 1, chain);
        printf("consume %d\n", *product);
        gquic_coroutine_yield(co);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int consumer_co_func(gquic_coroutine_t *const co, void *const chain) {
    static int machine = 1;

    for ( ;; ) {
        int *product = malloc(sizeof(int));
        *product = machine++;
        printf("product %d\n", *product);
        gquic_coroutine_chain_send(chain, GQUIC_COROUTINE_GET_SCHEDULE(co), product);
        if (machine % 3 == 0) {
            gquic_coroutine_yield(co);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(productor_consumer) {
    gquic_coroutine_schedule_t sche;
    gquic_coroutine_schedule_init(&sche);

    gquic_coroutine_chain_t chain;
    gquic_coroutine_chain_init(&chain);

    gquic_coroutine_t *productor_co = NULL;
    gquic_coroutine_alloc(&productor_co);
    gquic_coroutine_ctor(productor_co, 1024 * 1024, productor_co_func, &chain);

    gquic_coroutine_t *consumer_co = NULL;
    gquic_coroutine_alloc(&consumer_co);
    gquic_coroutine_ctor(consumer_co, 1024 * 1024, consumer_co_func, &chain);

    gquic_coroutine_schedule_join(&sche, consumer_co);
    gquic_coroutine_schedule_join(&sche, productor_co);
    int i = 0;
    for (i = 0; i < 10; i++) {
        gquic_coroutine_schedule_resume(&sche);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

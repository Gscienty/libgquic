#include "unit_test.h"
#include "coroutine/context.h"
#include "util/str.h"
#include <string.h>

gquic_couroutine_context_t main_ctx;
gquic_couroutine_context_t child_ctx;

GQUIC_UNIT_TEST(get_context) {
    gquic_couroutine_context_t ctx;
    ctx.parent = NULL;
    memset(ctx.regs, 0, sizeof(ctx.regs));
    gquic_coroutine_current_context(&ctx);
    GQUIC_UNIT_TEST_EXPECT(ctx.parent == NULL);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int maked_fn(void *const _) {
    (void) _;
    printf("HERE\n");
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

GQUIC_UNIT_TEST(make_context) {
    u_int8_t stack[4096] = { 0 };
    gquic_str_t data = { 4096, stack };

    child_ctx.stack.stack_pointer = stack;
    child_ctx.stack.stack_size = 4096;

    gquic_coroutine_make_context(&child_ctx, maked_fn, NULL);
    gquic_coroutine_current_context(&main_ctx);

    gquic_coroutine_swap_context(&main_ctx, &child_ctx);

    gquic_str_test_echo(&data);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

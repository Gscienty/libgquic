#ifndef _LIBGQUIC_COROUTINE_CONTEXT_H
#define _LIBGQUIC_COROUTINE_CONTEXT_H

#include <sys/types.h>

typedef struct gquic_coroutine_stack_s gquic_couroutine_stack_t;
struct gquic_coroutine_stack_s {
    void *stack_pointer;
    u_int64_t stack_size;
} __attribute__((packed));

typedef struct gquic_coroutine_context_s gquic_couroutine_context_t;
struct gquic_coroutine_context_s {
    gquic_couroutine_context_t *link;
    u_int8_t regs[256];
    gquic_couroutine_stack_t stack;
} __attribute__((packed));

int gquic_coroutine_current_context(gquic_couroutine_context_t *const ctx);
int gquic_coroutine_swap_context(gquic_couroutine_context_t *const from, gquic_couroutine_context_t *const to);
int gquic_coroutine_make_context(gquic_couroutine_context_t *const ctx, int (*fn) (void *const), void *const args);

#endif

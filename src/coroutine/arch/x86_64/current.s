.weak gquic_coroutine_current_context;
gquic_coroutine_current_context = __get_current_context;

.global __get_current_context;
.align 2;
.type __get_current_context, @function;
__get_current_context:
    movq %r8, 8(%rdi)
    movq %r9, 16(%rdi)
    movq %r10, 24(%rdi)
    movq %r11, 32(%rdi)
    movq %r12, 40(%rdi)
    movq %r13, 48(%rdi)
    movq %r14, 56(%rdi)
    movq %r15, 64(%rdi)
    movq %rdi, 72(%rdi)
    movq %rsi, 80(%rdi)
    movq %rbp, 88(%rdi)
    movq %rbx, 96(%rdi)
    movq %rdx, 104(%rdi)
    movq $1, 112(%rdi)
    movq %rcx, 120(%rdi)

    movq (%rsp), %rcx
    movq %rcx, 136(%rdi)

    leaq 8(%rsp), %rcx
    movq %rcx, 128(%rdi)

    xorl %eax, %eax
    ret
.end __get_current_context;
.size __get_current_context,.-__get_current_context;

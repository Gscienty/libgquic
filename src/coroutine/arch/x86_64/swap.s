.weak gquic_coroutine_swap_context;
gquic_coroutine_swap_context = __swap_context;

.global __swap_context;
.align 2;
.type __swap_context, @function;
__swap_context:
    /* save current context */
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

    /* recover their context */
    movq 8(%rsi), %r8
    movq 16(%rsi), %r9
    movq 24(%rsi), %r10
    movq 32(%rsi), %r11
    movq 40(%rsi), %r12
    movq 48(%rsi), %r13
    movq 56(%rsi), %r14
    movq 64(%rsi), %r15
    movq 72(%rsi), %rdi
    movq 88(%rsi), %rbp
    movq 96(%rsi), %rbx
    movq 104(%rsi), %rdx
    movq 112(%rsi), %rax
    movq 120(%rsi), %rcx
    movq 128(%rsi), %rsp

    pushq 136(%rsi)

    movq 80(%rsi), %rsi
    
    xorl %eax, %eax
    ret

.end __swap_context;
.size __swap_context,.-__swap_context;

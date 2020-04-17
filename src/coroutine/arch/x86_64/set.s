.global __set_context;
.align 2;
.type __set_context, @function;
__set_context:
    movq 8(%rdi), %r8
    movq 16(%rdi), %r9
    movq 24(%rdi), %r10
    movq 32(%rdi), %r11
    movq 40(%rdi), %r12
    movq 48(%rdi), %r13
    movq 56(%rdi), %r14
    movq 64(%rdi), %r15
    movq 80(%rdi), %rsi
    movq 88(%rdi), %rbp
    movq 96(%rdi), %rbx
    movq 104(%rdi), %rdx
    movq 112(%rdi), %rax
    movq 120(%rdi), %rcx
    movq 128(%rdi), %rsp

    pushq 136(%rdi)

    movq 72(%rdi), %rdi
    
    xorl %eax, %eax
    ret
.end __set_context;
.size __set_context,.-__set_context

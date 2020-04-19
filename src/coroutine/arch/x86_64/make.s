.weak gquic_coroutine_make_context;
gquic_coroutine_make_context = __make_context;

.global __make_context;
.align 2;
.type __make_context, @function;
__make_context:
    movq 264(%rdi), %rbx                ; // ctx.stack.stack_pointer 264(%rdi)
    addq 272(%rdi), %rbx                ; // ctx.stack.stack_pointer.stack_size 272(%rdi)
                                        ; // find coroutine stack pointer
    subq $8, %rbx
    andq $0xfffffffffffffff0, %rbx
    subq $8, %rbx

    movq %rsi, 136(%rdi)                ; // register RIP set func_ptr
    movq %rbx, %rax
    addq $8, %rax
    movq %rax, 96(%rdi)                 ; // register RBX set stack_pointer[8]
    movq %rbx, 128(%rdi)                ; // register RSP set stack_pointer

    movq $__end_context, (%rbx)         ; // put __end_context at bottom of stack
    movq (%rdi), %rax
    movq %rax, 8(%rbx)                  ; // put ctx.stack.link at bottom of stack

    movq %rdx, 72(%rdi)                 ; // put args

    xorl %eax, %eax
    ret
.end __make_context;
.size __make_context,.-__make_context;

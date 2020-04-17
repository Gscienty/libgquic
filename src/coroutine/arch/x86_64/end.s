.global __end_context;
.align 2;
.type __end_context, @function;
__end_context:
    movq %rbx, %rsp
    movq (%rsp), %rdi
    testq %rdi, %rdi

    je no_linked_context

    call __set_context@plt
    movq %rax, %rdi

no_linked_context:
    call exit@plt

    hlt

.end __end_context;
.size __end_context,.-__end_context;

#include "util/varint.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }
    gquic_util_varint_t var;
    gquic_varint_wrap(&var, atol(argv[1]));
    printf("%d\n", var.length);

    return 0;
}

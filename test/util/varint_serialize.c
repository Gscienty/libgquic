#include "util/varint.h"
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }

    gquic_varint_t var;
    gquic_varint_wrap(&var, atol(argv[1]));

    void *buf = malloc(var.length);
    if (buf == NULL) {
        return -2;
    }

    gquic_varint_serialize(&var, buf, var.length);
    int i;
    for (i = 0; i < var.length; i++) {
        unsigned char c = ((unsigned char *) buf)[i];
        printf("%02x", c);
    }
    printf("\n");

    return 0;
}

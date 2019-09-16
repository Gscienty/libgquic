#include "util/varint.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>

#define CHAR_2_HEX(n) ('0' <= (n) && (n) <= '9' ? ((n) - '0') : (((n) - 'a') + 10))

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }

    int str_size = strlen(argv[1]);
    void *buf = malloc(str_size / 2);

    int i = 0;
    for (i = 0; i < str_size; i += 2) {
        ((unsigned char *) buf)[i / 2] = CHAR_2_HEX(argv[1][i]) << 4;
        ((unsigned char *) buf)[i / 2] |= CHAR_2_HEX(argv[1][i + 1]);
    }

    gquic_varint_t varint;
    
    gquic_varint_deserialize(&varint, buf, str_size / 2);

    printf("%ld\n", varint.value);


    return 0;
}

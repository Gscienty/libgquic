#include "packet/packet_number.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }
    gquic_packet_number_t pn = atol(argv[1]);
    printf("%ld\n", gquic_packet_number_size(pn));
    return 0;
}

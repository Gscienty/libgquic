#include "packet/packet_number.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }

    printf("%ld\n", gquic_packet_number_flag_to_size(atoi(argv[1])));

    return 0;
}

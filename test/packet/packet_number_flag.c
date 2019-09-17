#include "packet/packet_number.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return -1;
    }
    printf("%d\n", gquic_packet_number_flag(atoi(argv[1])));

    return 0;
}

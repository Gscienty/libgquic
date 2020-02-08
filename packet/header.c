#include "packet/header.h"

int gquic_packet_header_init(gquic_packet_header_t *const header) {
    if (header == NULL) {
        return -1;
    }
    header->hdr.l_hdr = NULL;
    header->is_long = 0;

    return 0;
}

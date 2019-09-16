#include "packet/packet_number.h"

size_t gquic_packet_number_size(const gquic_packet_number_t pn) {
    if (pn <= 0xFF) {
        return 1;
    }
    else if (pn <= 0xFFFF) {
        return 2;
    }
    else if (pn <= 0xFFFFFFFF) {
        return 4;
    }
    else if (pn <= 0x3FFFFFFFFFFFFFFF) {
        return 8;
    }
    return 0;
}

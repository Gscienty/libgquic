#include "packet/packet_number.h"

size_t gquic_packet_number_size(const u_int64_t pn) {
    if (pn <= 0xFF) {
        return 1;
    }
    else if (pn <= 0xFFFF) {
        return 2;
    }
    else if (pn <= 0xFFFFFF) {
        return 3;
    }
    else if (pn <= 0x3FFFFFFF) {
        return 4;
    }
    return 0;
}

unsigned char gquic_packet_number_flag(const u_int64_t pn) {
    return gquic_packet_number_size(pn) - 1;
}

size_t gquic_packet_number_flag_to_size(const u_int8_t flag) {
    return (flag & 0x03) + 1;
}

int gquic_packet_number_gen_init(gquic_packet_number_gen_t *const gen) {
    if (gen == NULL) {
        return -1;
    }
    gen->average = 0;
    gen->next = 0;
    gen->skip = 0;
    gquic_list_head_init(&gen->mem);

    return 0;
}

int gquic_packet_number_gen_dtor(gquic_packet_number_gen_t *const gen) {
    if (gen == NULL) {
        return -1;
    }
    while (!gquic_list_head_empty(&gen->mem)) {
        gquic_list_release(GQUIC_LIST_FIRST(&gen->mem));
    }

    return 0;
}


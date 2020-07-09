#include "packet/packet_number.h"
#include "exception.h"
#include <openssl/rand.h>

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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gen->average = 0;
    gen->next = 0;
    gen->skip = 0;
    gen->mem_count = 0;
    gquic_list_head_init(&gen->mem);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_number_gen_ctor(gquic_packet_number_gen_t *const gen, const u_int64_t init_pn, const u_int64_t average) {
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gen->next = init_pn;
    gen->average = average;
    gquic_packet_number_gen_new_skip(gen);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_number_gen_dtor(gquic_packet_number_gen_t *const gen) {
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (!gquic_list_head_empty(&gen->mem)) {
        gquic_list_release(GQUIC_LIST_FIRST(&gen->mem));
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_number_gen_new_skip(gquic_packet_number_gen_t *const gen) {
    u_int16_t num;
    u_int64_t skip;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    RAND_bytes((u_int8_t *) &num, 2);
    skip = num * (gen->average - 1) / 0x7FFF;
    gen->skip = gen->next + 2 + skip;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_number_gen_next(u_int64_t *const pn, gquic_packet_number_gen_t *const gen) {
    u_int64_t *mem_pn = NULL;
    if (gen == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *pn = gen->next;

    gen->next++;
    if (gen->next == gen->skip) {
        if (gen->mem_count >= 10) {
            gquic_list_release(GQUIC_LIST_FIRST(&gen->mem));
            gen->mem_count--;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_list_alloc((void **) &mem_pn, sizeof(u_int64_t)));
        *mem_pn = gen->next;
        gquic_list_insert_before(&gen->mem, mem_pn);
        gen->next++;
        gquic_packet_number_gen_new_skip(gen);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_number_gen_valid(gquic_packet_number_gen_t *const gen, const gquic_list_t *const blocks) {
    u_int64_t *pn = NULL;
    if (gen == NULL || blocks == NULL) {
        return 0;
    }
    GQUIC_LIST_FOREACH(pn, &gen->mem) {
        if (gquic_frame_ack_blocks_contain_packet(blocks, *pn)) {
            return 0;
        }
    }
    return 1;
}

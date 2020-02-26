#ifndef _LIBGQUIC_FRAME_PARSER_H
#define _LIBGQUIC_FRAME_PARSER_H

#include "util/str.h"

typedef struct gquic_frame_parser_s gquic_frame_parser_t;
struct gquic_frame_parser_s {
    int ack_delay_exponent;
};

int gquic_frame_parser_init(gquic_frame_parser_t *const parser);

int gquic_frame_parser_next(void **const frame_storage, gquic_frame_parser_t *const parser, gquic_reader_str_t *const reader, const u_int8_t enc_lv);

#endif

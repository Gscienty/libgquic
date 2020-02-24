#ifndef _LIBGQUIC_FRAME_PARSER_H
#define _LIBGQUIC_FRAME_PARSER_H

typedef struct gquic_frame_parser_s gquic_frame_parser_t;
struct gquic_frame_parser_s {
    int ack_delay_exponent;
};

int gquic_frame_parser_init(gquic_frame_parser_t *const parser);

#endif

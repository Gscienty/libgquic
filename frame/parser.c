#include "frame/parser.h"
#include <stddef.h>

int gquic_frame_parser_init(gquic_frame_parser_t *const parser) {
    if (parser == NULL) {
        return -1;
    }
    parser->ack_delay_exponent = 0;

    return 0;
}

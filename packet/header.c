#include "packet/header.h"

int gquic_packet_header_init(gquic_packet_header_t *const header) {
    if (header == NULL) {
        return -1;
    }
    header->hdr.l_hdr = NULL;
    header->hdr.s_hdr = NULL;
    header->is_long = 0;

    return 0;
}

u_int64_t gquic_packet_header_get_pn(gquic_packet_header_t *const header) {
    if (header == NULL || (header->hdr.l_hdr == NULL && header->hdr.s_hdr == NULL)) {
        return 0;
    }
    if (header->is_long) {
        switch (gquic_packet_long_header_type(header->hdr.l_hdr)) {
        case GQUIC_LONG_HEADER_INITIAL:
            return ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn;
        case GQUIC_LONG_HEADER_HANDSHAKE:
            return ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn;
        case GQUIC_LONG_HEADER_0RTT:
            return ((gquic_packet_0rtt_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn;
        }
        return (u_int64_t) -1;
    }
    else {
        return header->hdr.s_hdr->pn;
    }
}

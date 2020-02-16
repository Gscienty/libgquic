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

int gquic_packet_header_set_pn(gquic_packet_header_t *const header, const u_int64_t pn) {
    if (header == NULL || (header->hdr.l_hdr == NULL && header->hdr.s_hdr == NULL)) {
        return -1;
    }
    if (header->is_long) {
        switch (gquic_packet_long_header_type(header->hdr.l_hdr)) {
        case GQUIC_LONG_HEADER_INITIAL:
            ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn = pn;
            break;
        case GQUIC_LONG_HEADER_HANDSHAKE:
            ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn = pn;
            break;
        case GQUIC_LONG_HEADER_0RTT:
            ((gquic_packet_0rtt_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->pn = pn;
            break;
        default:
            return -2;
        }
        return 0;
    }
    else {
        header->hdr.s_hdr->pn = pn;
        return 0;
    }
}

int gquic_packet_header_set_len(gquic_packet_header_t *const header, const u_int64_t len) {
    if (header == NULL) {
        return -1;
    }
    if (header->is_long) {
        switch (gquic_packet_long_header_type(header->hdr.l_hdr)) {
        case GQUIC_LONG_HEADER_INITIAL:
            ((gquic_packet_initial_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->len = len;
            break;
        case GQUIC_LONG_HEADER_HANDSHAKE:
            ((gquic_packet_handshake_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->len = len;
            break;
        case GQUIC_LONG_HEADER_0RTT:
            ((gquic_packet_0rtt_header_t *) GQUIC_LONG_HEADER_SPEC(header->hdr.l_hdr))->len = len;
            break;
        }
    }

    return 0;
}

size_t gquic_packet_header_size(gquic_packet_header_t *const header) {
    if (header == NULL) {
        return 0;
    }
    if (header->is_long) {
        return gquic_packet_long_header_size(header->hdr.l_hdr);
    }
    else {
        return gquic_packet_short_header_size(header->hdr.s_hdr);
    }
}

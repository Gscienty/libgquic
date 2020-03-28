#include "packet/header.h"
#include "exception.h"
#include <malloc.h>

int gquic_packet_header_init(gquic_packet_header_t *const header) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    header->hdr.l_hdr = NULL;
    header->hdr.s_hdr = NULL;
    header->is_long = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_header_dtor(gquic_packet_header_t *const header) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (header->is_long) {
        if (header->hdr.l_hdr != NULL) {
            free(header->hdr.l_hdr);
        }
    }
    else {
        if (header->hdr.s_hdr != NULL) {
            free(header->hdr.s_hdr);
        }
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
        }
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
    else {
        header->hdr.s_hdr->pn = pn;
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }
}

int gquic_packet_header_set_len(gquic_packet_header_t *const header, const u_int64_t len) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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

int gquic_packet_header_deserialize_conn_id(gquic_str_t *const conn_id, const gquic_str_t *const data, const int conn_id_len) {
    int dst_conn_id_len = 0;
    if (conn_id == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if ((GQUIC_STR_FIRST_BYTE(data) & 0x80) != 0) {
        if (GQUIC_STR_SIZE(data) < 6) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        dst_conn_id_len = ((u_int8_t *) GQUIC_STR_VAL(data))[5];
        if (GQUIC_STR_SIZE(data) < (u_int64_t) 6 + dst_conn_id_len) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        conn_id->size = dst_conn_id_len;
        conn_id->val = GQUIC_STR_VAL(data) + 6;
    }
    else {
        if (GQUIC_STR_SIZE(data) < (u_int64_t) 1 + conn_id_len) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        conn_id->size = conn_id_len;
        conn_id->val = GQUIC_STR_VAL(data) + 1;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_header_deserialize_src_conn_id(gquic_str_t *const conn_id, const gquic_str_t *const data) {
    gquic_reader_str_t reader = { 0, NULL };
    u_int8_t src_conn_id_len;
    if (conn_id == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    reader = *data;
    gquic_reader_str_readed_size(&reader, 1 + 4 + 1 + ((u_int8_t *) GQUIC_STR_VAL(data))[1 + 4]);
    src_conn_id_len = gquic_reader_str_read_byte(&reader);
    conn_id->size = src_conn_id_len;
    conn_id->val = GQUIC_STR_VAL(&reader);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_packet_header_deserialize_packet_len(u_int64_t *const packet_len,
                                               const gquic_str_t *const data,
                                               const int conn_id_len) {
    gquic_reader_str_t reader = { 0, NULL };
    u_int64_t tmp = 0;
    u_int64_t header_len = 0;
    u_int64_t payload_len = 0;
    if (packet_len == NULL || data == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    reader = *data;

    if ((GQUIC_STR_FIRST_BYTE(data) & 0x80) != 0) {
        if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, 1 + 4))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, gquic_reader_str_read_byte(&reader)))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, gquic_reader_str_read_byte(&reader)))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        switch ((GQUIC_STR_FIRST_BYTE(data) & 0x30) >> 4) {
        case 0x00:
            if (GQUIC_ASSERT(gquic_varint_deserialize(&tmp, &reader))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
            if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, tmp))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
            if (GQUIC_ASSERT(gquic_varint_deserialize(&payload_len, &reader))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
            break;
        case 0x01:
            if (GQUIC_ASSERT(gquic_varint_deserialize(&payload_len, &reader))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
            break;
        case 0x02:
            if (GQUIC_ASSERT(gquic_varint_deserialize(&payload_len, &reader))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
            break;
        case 0x03:
            tmp = gquic_reader_str_read_byte(&reader);
            if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, tmp))) {
                GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
            }
        }
    }
    else {
        if (GQUIC_ASSERT(gquic_reader_str_readed_size(&reader, 1 + conn_id_len))) {
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
        }
        payload_len = GQUIC_STR_SIZE(&reader);
    }
    header_len = GQUIC_STR_VAL(&reader) - GQUIC_STR_VAL(data);
    *packet_len = header_len + payload_len;
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

u_int8_t gquic_packet_header_deserlialize_type(const gquic_str_t *const data) {
    if (data == NULL) {
        return 0;
    }
    if ((GQUIC_STR_FIRST_BYTE(data) & 0x80) != 0) {
        switch ((GQUIC_STR_FIRST_BYTE(data) & 0x30) >> 4) {
        case 0x00:
            return GQUIC_LONG_HEADER_INITIAL;
        case 0x01:
            return GQUIC_LONG_HEADER_0RTT;
        case 0x02:
            return GQUIC_LONG_HEADER_HANDSHAKE;
        case 0x03:
            return GQUIC_LONG_HEADER_RETRY;
        }
        return 0;
    }
    else {
        return GQUIC_SHORT_HEADER;
    }
}

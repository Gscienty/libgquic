#include "packet/short_header_packet.h"
#include "packet/packet_number.h"
#include "util/big_endian.h"
#include "exception.h"
#include <malloc.h>
#include <string.h>

gquic_packet_short_header_t *gquic_packet_short_header_alloc() {
    gquic_packet_short_header_t *header = malloc(sizeof(gquic_packet_short_header_t));
    if (header == NULL) {
        return NULL;
    }
    memset(header->dcid, 0, sizeof(header->dcid));
    header->dcid_len = 0;
    header->flag = 0;
    header->pn = 0;

    return header;
}

ssize_t gquic_packet_short_header_size(const gquic_packet_short_header_t *const header) {
    if (header == NULL) {
        return 0;
    }
    return 1 + header->dcid_len + gquic_packet_number_flag_to_size(header->flag);
}

int gquic_packet_short_header_serialize(const gquic_packet_short_header_t *const header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if ((size_t) gquic_packet_short_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY;
    }
    gquic_writer_str_write_byte(writer, header->flag);
    gquic_str_t dcid = { header->dcid_len, (void *) header->dcid };
    gquic_writer_str_write(writer, &dcid);

    switch (gquic_packet_number_flag_to_size(header->flag)) {
    case 1:
        gquic_big_endian_writer_1byte(writer, header->pn);
        break;
    case 2:
        gquic_big_endian_writer_2byte(writer, header->pn);
        break;
    case 3:
        gquic_big_endian_writer_3byte(writer, header->pn);
        break;
    case 4:
        gquic_big_endian_writer_4byte(writer, header->pn);
        break;
    }
    return GQUIC_SUCCESS;
}

int gquic_packet_short_header_deserialize(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    header->flag = gquic_reader_str_read_byte(reader);
    gquic_str_t dcid = { header->dcid_len, header->dcid };
    gquic_reader_str_read(&dcid, reader);
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(header->flag)) {
    case 1:
        gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader);
        break;
    case 2:
        gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader);
        break;
    case 3:
        gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader);
        break;
    case 4:
        gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader);
        break;
    }
    return GQUIC_SUCCESS;
}

int gquic_packet_short_header_deserialize_unseal_part(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    header->flag = gquic_reader_str_read_byte(reader);
    gquic_str_t dcid = { header->dcid_len, header->dcid };
    gquic_reader_str_read(&dcid, reader);
    header->pn = 0;

    return GQUIC_SUCCESS;
}

int gquic_packet_short_header_deserialize_seal_part(gquic_packet_short_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }

    switch (gquic_packet_number_flag_to_size(header->flag)) {
    case 1:
        gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader);
        break;
    case 2:
        gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader);
        break;
    case 3:
        gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader);
        break;
    case 4:
        gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader);
        break;
    }
    return GQUIC_SUCCESS;
}


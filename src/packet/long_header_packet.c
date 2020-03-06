#include "packet/long_header_packet.h"
#include "util/big_endian.h"
#include <malloc.h>
#include <string.h>

#define __Max(x, y) ((x) > (y) ? (x) : (y))

static size_t gquic_packet_initial_header_size(const gquic_packet_initial_header_t *);
static size_t gquic_packet_0rtt_header_size(const gquic_packet_0rtt_header_t *);
static size_t gquic_packet_handshake_header_size(const gquic_packet_handshake_header_t *);
static size_t gquic_packet_retry_header_size(const gquic_packet_retry_header_t *);

static int gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *, gquic_writer_str_t *const);
static int gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *, gquic_writer_str_t *const);
static int gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *, gquic_writer_str_t *const);
static int gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *, gquic_writer_str_t *const);

static int gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *, gquic_reader_str_t *const);
static int gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *, gquic_reader_str_t *const);
static int gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *, gquic_reader_str_t *const);
static int gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *, gquic_reader_str_t *const);

static int gquic_packet_initial_header_deserialize_unseal_part(gquic_packet_initial_header_t *, gquic_reader_str_t *const);
static int gquic_packet_handshake_header_deserialize_unseal_part(gquic_packet_handshake_header_t *, gquic_reader_str_t *const);
static int gquic_packet_initial_header_deserialize_seal_part(gquic_packet_initial_header_t *, gquic_reader_str_t *const);
static int gquic_packet_handshake_header_deserialize_seal_part(gquic_packet_handshake_header_t *, gquic_reader_str_t *const);

const static size_t SUB_MAX_SIZE = __Max(
                                         __Max(sizeof(gquic_packet_0rtt_header_t),
                                               sizeof(gquic_packet_retry_header_t)),
                                         __Max(sizeof(gquic_packet_initial_header_t),
                                               sizeof(gquic_packet_handshake_header_t)));

gquic_packet_long_header_t *gquic_packet_long_header_alloc() {
    gquic_packet_long_header_t *header = malloc(sizeof(gquic_packet_long_header_t) + SUB_MAX_SIZE);
    if (header == NULL) {
        return NULL;
    }
    return header;
}

size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *const header) {
    if (header == NULL) {
        return 0;
    }
    size_t common = 1 + 4 + 1 + header->dcid_len + 1 + header->scid_len;
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        return common + gquic_packet_initial_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x01:
        return common + gquic_packet_0rtt_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x02:
        return common + gquic_packet_handshake_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x03:
        return common + gquic_packet_retry_header_size(GQUIC_LONG_HEADER_SPEC(header));
    }
    return 0;
}

int gquic_packet_long_header_release(gquic_packet_long_header_t *const header) {
    gquic_packet_initial_header_t *initial_header_spec = NULL;
    if (header == NULL) {
        return -1;
    }
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        initial_header_spec = GQUIC_LONG_HEADER_SPEC(header);
        if (initial_header_spec->token != NULL) {
            free(initial_header_spec->token);
        }
        break;
    }
    free(header);
    return 0;
}

int gquic_packet_long_header_serialize(const gquic_packet_long_header_t *const header, gquic_writer_str_t *const writer) {
    int ret = 0;
    if (header == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_packet_long_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return -3;
    }

    gquic_writer_str_write_byte(writer, header->flag);
    
    gquic_big_endian_writer_4byte(writer, header->version);

    gquic_writer_str_write_byte(writer, header->dcid_len);
    gquic_str_t dcid_str = { header->dcid_len, (void *) header->dcid };
    gquic_writer_str_write(writer, &dcid_str);

    gquic_writer_str_write_byte(writer, header->scid_len);
    gquic_str_t scid_str = { header->scid_len, (void *) header->scid };
    gquic_writer_str_write(writer, &scid_str);

    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        ret = gquic_packet_initial_header_serialize(GQUIC_LONG_HEADER_SPEC(header), writer);
        break;
    case 0x01:
        ret = gquic_packet_0rtt_header_serialize(GQUIC_LONG_HEADER_SPEC(header), writer);
        break;
    case 0x02:
        ret = gquic_packet_handshake_header_serialize(GQUIC_LONG_HEADER_SPEC(header), writer);
        break;
    case 0x03:
        ret = gquic_packet_retry_header_serialize(GQUIC_LONG_HEADER_SPEC(header), writer);
        break;
    }
    if (ret != 0) {
        return -4;
    }

    return 0;
}

int gquic_packet_long_header_deserialize(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    int ret = 0;
    if (header == NULL) {
        return -1;
    }
    header->flag = gquic_reader_str_read_byte(reader);

    gquic_big_endian_reader_4byte(&header->version, reader);

    header->dcid_len = gquic_reader_str_read_byte(reader);
    gquic_str_t dcid = { header->dcid_len, header->dcid };
    gquic_reader_str_read(&dcid, reader);

    header->scid_len = gquic_reader_str_read_byte(reader);
    gquic_str_t scid = { header->scid_len, header->scid };
    gquic_reader_str_read(&scid, reader);

    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        ret = gquic_packet_initial_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    case 0x01:
        ret = gquic_packet_0rtt_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    case 0x02:
        ret = gquic_packet_handshake_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    case 0x03:
        ret = gquic_packet_retry_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    }
    if (ret != 0) {
        return -4;
    }
    return 0;
}

int gquic_packet_long_header_deserialize_unseal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    int ret = 0;
    if (header == NULL) {
        return -1;
    }
    header->flag = gquic_reader_str_read_byte(reader);

    gquic_big_endian_reader_4byte(&header->version, reader);

    header->dcid_len = gquic_reader_str_read_byte(reader);
    gquic_str_t dcid = { header->dcid_len, header->dcid };
    gquic_reader_str_read(&dcid, reader);

    header->scid_len = gquic_reader_str_read_byte(reader);
    gquic_str_t scid = { header->scid_len, header->scid };
    gquic_reader_str_read(&scid, reader);

    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        ret = gquic_packet_initial_header_deserialize_unseal_part(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    case 0x02:
        ret = gquic_packet_handshake_header_deserialize_unseal_part(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    default:
        return -2;
    }
    if (ret != 0) {
        return -3;
    }
    return 0;
}

static size_t gquic_packet_initial_header_size(const gquic_packet_initial_header_t *header) {
    if (header == NULL) {
        return 0;
    }
    return gquic_varint_size(&header->len)
        + gquic_varint_size(&header->token_len)
        + header->token_len
        + gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
}

static size_t gquic_packet_0rtt_header_size(const gquic_packet_0rtt_header_t *header) {
    return gquic_varint_size(&header->len)
        + gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
}

static size_t gquic_packet_handshake_header_size(const gquic_packet_handshake_header_t *header) {
    return gquic_varint_size(&header->len)
        + gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
}

static size_t gquic_packet_retry_header_size(const gquic_packet_retry_header_t *header) {
    return 1 + header->odcid_len;
}

static int gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_packet_initial_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return -3;
    }
    if (gquic_varint_serialize(&header->token_len, writer) != 0) {
        return -4;
    }

    gquic_str_t token = { header->token_len, header->token };
    gquic_writer_str_write(writer, &token);

    if (gquic_varint_serialize(&header->len, writer) != 0) {
        return -5;
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    
    return 0;
}

static int gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_packet_0rtt_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_varint_serialize(&header->len, writer) != 0) {
        return -3;
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_packet_handshake_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    if (gquic_varint_serialize(&header->len, writer) != 0) {
        return -3;
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        return -1;
    }
    if (gquic_packet_retry_header_size(header) > GQUIC_STR_SIZE(writer)) {
        return -2;
    }
    gquic_writer_str_write_byte(writer, header->odcid_len);
    gquic_str_t odcid = { header->odcid_len, (void *) header->odcid };
    gquic_writer_str_write(&odcid, writer);
    return 0;
}

static int gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_varint_deserialize(&header->token_len, reader) != 0) {
        return -2;
    }
    if (header->token_len > GQUIC_STR_SIZE(reader)) {
        return -3;
    }
    header->token = malloc(header->token_len);
    if (header->token == NULL) {
        return -4;
    }
    gquic_str_t token = { header->token_len, header->token };
    if (gquic_reader_str_read(&token, reader) != 0) {
        return -5;
    }
    if (gquic_varint_deserialize(&header->len, reader) != 0) {
        return -6;
    }
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_varint_deserialize(&header->len, reader) != 0) {
        return -2;
    }
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_varint_deserialize(&header->len, reader) != 0) {
        return -2;
    }
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    header->odcid_len = gquic_reader_str_read_byte(reader);
    if (header->odcid_len > GQUIC_STR_SIZE(reader)) {
        return -3;
    }
    gquic_str_t odcid = { header->odcid_len, header->odcid };
    gquic_reader_str_read(&odcid, reader);
    return 0;
}

u_int8_t gquic_packet_long_header_type(const gquic_packet_long_header_t *const header) {
    if (header == NULL) {
        return 0;
    }

    switch ((header->flag & 0x30) >> 4) {
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

static int gquic_packet_initial_header_deserialize_unseal_part(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_varint_deserialize(&header->token_len, reader) != 0) {
        return -2;
    }
    if (header->token_len > GQUIC_STR_SIZE(reader)) {
        return -3;
    }
    header->token = malloc(header->token_len);
    if (header->token == NULL) {
        return -4;
    }
    gquic_str_t token = { header->token_len, header->token };
    if (gquic_reader_str_read(&token, reader) != 0) {
        return -5;
    }
    if (gquic_varint_deserialize(&header->len, reader) != 0) {
        return -6;
    }
    header->pn = 0;
    return 0;
}

static int gquic_packet_handshake_header_deserialize_unseal_part(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    if (gquic_varint_deserialize(&header->len, reader) != 0) {
        return -2;
    }
    header->pn = 0;
    return 0;
}

int gquic_packet_long_header_deserialize_seal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    int ret = 0;
    if (header == NULL || reader == NULL) {
        return -1;
    }
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        ret = gquic_packet_initial_header_deserialize_seal_part(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    case 0x02:
        ret = gquic_packet_handshake_header_deserialize_seal_part(GQUIC_LONG_HEADER_SPEC(header), reader);
        break;
    default:
        return -2;
    }

    return ret;
}

static int gquic_packet_initial_header_deserialize_seal_part(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

static int gquic_packet_handshake_header_deserialize_seal_part(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        return -1;
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
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
    return 0;
}

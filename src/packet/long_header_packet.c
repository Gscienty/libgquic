/* src/packet/long_header_packet.c 长首部
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "packet/long_header_packet.h"
#include "util/big_endian.h"
#include "util/malloc.h"
#include "exception.h"
#include <string.h>

#define __Max(x, y) ((x) > (y) ? (x) : (y))

/**
 * 具体长首部的长度
 *
 * @param header: 具体长首部
 *
 * @return: 长度
 */
static size_t gquic_packet_initial_header_size(const gquic_packet_initial_header_t *const header);
static size_t gquic_packet_0rtt_header_size(const gquic_packet_0rtt_header_t *const header);
static size_t gquic_packet_handshake_header_size(const gquic_packet_handshake_header_t *const header);
static size_t gquic_packet_retry_header_size(const gquic_packet_retry_header_t *const header);

/**
 * 具体长首部序列化操作
 *
 * @param header: 具体长首部
 * @param writer: writer
 * 
 * @return: exception
 */
static gquic_exception_t gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *const header, gquic_writer_str_t *const writer);
static gquic_exception_t gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *const header, gquic_writer_str_t *const writer);
static gquic_exception_t gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *const header, gquic_writer_str_t *const writer);
static gquic_exception_t gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *const header, gquic_writer_str_t *const writer);

/**
 * 长首部反序列化
 *
 * @param header: 具体长首部
 * @param reader: reader
 * 
 * @return: exception
 */
static gquic_exception_t gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *const header, gquic_reader_str_t *const reader);
static gquic_exception_t gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *const header, gquic_reader_str_t *const reader);
static gquic_exception_t gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *const header, gquic_reader_str_t *const reader);
static gquic_exception_t gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *const header, gquic_reader_str_t *const reader);


/**
 * 长首部反序列化未加密部分
 *
 * @param header: 长首部
 * @param reader: reader
 * 
 * @return: exception
 */
static gquic_exception_t gquic_packet_initial_header_deserialize_unseal_part(gquic_packet_initial_header_t *const header, gquic_reader_str_t *const reader);
static gquic_exception_t gquic_packet_handshake_header_deserialize_unseal_part(gquic_packet_handshake_header_t *const header, gquic_reader_str_t *const reader);

/**
 * 长首部反序列化加密部分
 *
 * @param header: 长首部
 * @param reader: reader
 * 
 * @return: exception
 */
static gquic_exception_t gquic_packet_initial_header_deserialize_seal_part(gquic_packet_initial_header_t *const header, gquic_reader_str_t *const reader);
static gquic_exception_t gquic_packet_handshake_header_deserialize_seal_part(gquic_packet_handshake_header_t *const header, gquic_reader_str_t *const reader);

const static size_t SUB_MAX_SIZE = __Max(
                                         __Max(sizeof(gquic_packet_0rtt_header_t),
                                               sizeof(gquic_packet_retry_header_t)),
                                         __Max(sizeof(gquic_packet_initial_header_t),
                                               sizeof(gquic_packet_handshake_header_t)));

gquic_exception_t gquic_packet_long_header_alloc(gquic_packet_long_header_t **const header_storage) {
    if (header_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_PROCESS_DONE(gquic_malloc((void **) header_storage, sizeof(gquic_packet_long_header_t) + SUB_MAX_SIZE));
}

size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *const header) {
    if (header == NULL) {
        return 0;
    }
    size_t common = 1 + 4 + 1 + header->dcid_len + 1 + header->scid_len;
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        return common + gquic_packet_initial_header_size(GQUIC_LONG_HEADER_SPEC(void, header));
    case 0x01:
        return common + gquic_packet_0rtt_header_size(GQUIC_LONG_HEADER_SPEC(void, header));
    case 0x02:
        return common + gquic_packet_handshake_header_size(GQUIC_LONG_HEADER_SPEC(void, header));
    case 0x03:
        return common + gquic_packet_retry_header_size(GQUIC_LONG_HEADER_SPEC(void, header));
    }

    return 0;
}

gquic_exception_t gquic_packet_long_header_release(gquic_packet_long_header_t *const header) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        if (GQUIC_LONG_HEADER_SPEC(gquic_packet_initial_header_t, header)->token != NULL) {
            gquic_free(GQUIC_LONG_HEADER_SPEC(gquic_packet_initial_header_t, header)->token);
        }
        break;
    }

    gquic_free(header);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_long_header_serialize(const gquic_packet_long_header_t *const header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_long_header_size(header) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
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
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_initial_header_serialize(GQUIC_LONG_HEADER_SPEC(void, header), writer));
        break;
    case 0x01:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_0rtt_header_serialize(GQUIC_LONG_HEADER_SPEC(void, header), writer));
        break;
    case 0x02:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_handshake_header_serialize(GQUIC_LONG_HEADER_SPEC(void, header), writer));
        break;
    case 0x03:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_retry_header_serialize(GQUIC_LONG_HEADER_SPEC(void, header), writer));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_long_header_deserialize(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_initial_header_deserialize(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    case 0x01:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_0rtt_header_deserialize(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    case 0x02:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_handshake_header_deserialize(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    case 0x03:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_retry_header_deserialize(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_long_header_deserialize_unseal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
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
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_initial_header_deserialize_unseal_part(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    case 0x02:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_handshake_header_deserialize_unseal_part(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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

static gquic_exception_t gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_initial_header_size(header) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&header->token_len, writer));

    gquic_str_t token = { header->token_len, header->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_writer_str_write(writer, &token));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&header->len, writer));

    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, header->pn));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, header->pn));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_3byte(writer, header->pn));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, header->pn));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }
    
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_0rtt_header_size(header) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&header->len, writer));
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, header->pn));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, header->pn));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_3byte(writer, header->pn));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, header->pn));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_handshake_header_size(header) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_serialize(&header->len, writer));
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_1byte(writer, header->pn));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_2byte(writer, header->pn));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_3byte(writer, header->pn));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_writer_4byte(writer, header->pn));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *header, gquic_writer_str_t *const writer) {
    if (header == NULL || writer == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (gquic_packet_retry_header_size(header) > GQUIC_STR_SIZE(writer)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_writer_str_write_byte(writer, header->odcid_len);
    gquic_str_t odcid = { header->odcid_len, (void *) header->odcid };
    gquic_writer_str_write(&odcid, writer);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->token_len, reader));
    if (header->token_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &header->token, header->token_len));
    gquic_str_t token = { header->token_len, header->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->len, reader));
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->len, reader));
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
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->len, reader));
    header->pn = 0;
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    header->odcid_len = gquic_reader_str_read_byte(reader);
    if (header->odcid_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    gquic_str_t odcid = { header->odcid_len, header->odcid };
    gquic_reader_str_read(&odcid, reader);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
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

static gquic_exception_t gquic_packet_initial_header_deserialize_unseal_part(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->token_len, reader));
    if (header->token_len > GQUIC_STR_SIZE(reader)) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_malloc((void **) &header->token, header->token_len));
    gquic_str_t token = { header->token_len, header->token };
    GQUIC_ASSERT_FAST_RETURN(gquic_reader_str_read(&token, reader));
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->len, reader));
    header->pn = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handshake_header_deserialize_unseal_part(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_ASSERT_FAST_RETURN(gquic_varint_deserialize(&header->len, reader));
    header->pn = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_packet_long_header_deserialize_seal_part(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_initial_header_deserialize_seal_part(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    case 0x02:
        GQUIC_ASSERT_FAST_RETURN(gquic_packet_handshake_header_deserialize_seal_part(GQUIC_LONG_HEADER_SPEC(void, header), reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_HEADER_TYPE_UNEXCEPTED);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_initial_header_deserialize_seal_part(gquic_packet_initial_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_packet_handshake_header_deserialize_seal_part(gquic_packet_handshake_header_t *header, gquic_reader_str_t *const reader) {
    if (header == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    switch (gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag)) {
    case 1:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_1byte((u_int8_t *) &header->pn, reader));
        break;
    case 2:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_2byte((u_int16_t *) &header->pn, reader));
        break;
    case 3:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_3byte((u_int32_t *) &header->pn, reader));
        break;
    case 4:
        GQUIC_ASSERT_FAST_RETURN(gquic_big_endian_reader_4byte((u_int32_t *) &header->pn, reader));
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_HEADER_NUMBER_FLAG_SIZE);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

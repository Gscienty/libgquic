#include "frame/parser.h"
#include "frame/meta.h"
#include "frame/stream.h"
#include "frame/stream_pool.h"
#include "frame/ping.h"
#include "frame/ack.h"
#include "frame/reset_stream.h"
#include "frame/stop_sending.h"
#include "frame/crypto.h"
#include "frame/new_token.h"
#include "frame/max_data.h"
#include "frame/max_stream_data.h"
#include "frame/max_streams.h"
#include "frame/data_blocked.h"
#include "frame/stream_data_blocked.h"
#include "frame/streams_blocked.h"
#include "frame/new_connection_id.h"
#include "frame/retire_connection_id.h"
#include "frame/path_challenge.h"
#include "frame/path_response.h"
#include "frame/connection_close.h"
#include "tls/common.h"
#include "exception.h"
#include <stddef.h>

static int gquic_frame_parser_parse(void **const, gquic_frame_parser_t *const, gquic_reader_str_t *const, const u_int8_t);

int gquic_frame_parser_init(gquic_frame_parser_t *const parser) {
    if (parser == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    parser->ack_delay_exponent = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

int gquic_frame_parser_next(void **const frame_storage, gquic_frame_parser_t *const parser, gquic_reader_str_t *const reader, const u_int8_t enc_lv) {
    if (frame_storage == NULL || parser == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    while (GQUIC_STR_SIZE(reader) != 0) {
        if (GQUIC_STR_FIRST_BYTE(reader) == 0x00) {
            gquic_reader_str_read_byte(reader);
            continue;
        }
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_parser_parse(frame_storage, parser, reader, enc_lv));
        GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static int gquic_frame_parser_parse(void **const frame_storage,
                                    gquic_frame_parser_t *const parser,
                                    gquic_reader_str_t *const reader,
                                    const u_int8_t enc_lv) {
    if (frame_storage == NULL || parser == NULL || reader == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    *frame_storage = NULL;

    switch (enc_lv) {
    case GQUIC_ENC_LV_INITIAL:
    case GQUIC_ENC_LV_HANDSHAKE:
        switch (GQUIC_STR_FIRST_BYTE(reader)) {
        case 0x01: // ping
        case 0x02:
        case 0x03: // ack
        case 0x06: // crypto
        case 0x1c:
        case 0x1d: // conn close
            break;
        default:
            GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ENC_LV_FRAME_CONFLICT);
        }
        break;
    case GQUIC_ENC_LV_1RTT:
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_ENC_LV);
    }

    if ((GQUIC_STR_FIRST_BYTE(reader) & 0xf8) == 0x08) {
        GQUIC_ASSERT_FAST_RETURN(gquic_stream_frame_pool_get((gquic_frame_stream_t **) frame_storage));
    }
    else switch (GQUIC_STR_FIRST_BYTE(reader)) {
    case 0x01:
        *frame_storage = gquic_frame_ping_alloc();
        break;
    case 0x02:
    case 0x03:
        *frame_storage = gquic_frame_ack_alloc(); // TODO ack delay exponent
        break;
    case 0x04:
        *frame_storage = gquic_frame_reset_stream_alloc();
        break;
    case 0x05:
        *frame_storage = gquic_frame_stop_sending_alloc();
        break;
    case 0x06:
        *frame_storage = gquic_frame_crypto_alloc();
        break;
    case 0x07:
        *frame_storage = gquic_frame_new_token_alloc();
        break;
    case 0x10:
        *frame_storage = gquic_frame_max_data_alloc();
        break;
    case 0x11:
        *frame_storage = gquic_frame_max_stream_data_alloc();
        break;
    case 0x12:
    case 0x13:
        *frame_storage = gquic_frame_max_streams_alloc();
        break;
    case 0x14:
        *frame_storage = gquic_frame_data_blocked_alloc();
        break;
    case 0x15:
        *frame_storage = gquic_frame_stream_data_blocked_alloc();
        break;
    case 0x16:
    case 0x17:
        *frame_storage = gquic_frame_streams_blocked_alloc();
        break;
    case 0x18:
        *frame_storage = gquic_frame_new_connection_id_alloc();
        break;
    case 0x19:
        *frame_storage = gquic_frame_retire_connection_id_alloc();
        break;
    case 0x1a:
        *frame_storage = gquic_frame_path_challenge_alloc();
        break;
    case 0x1b:
        *frame_storage = gquic_frame_path_response_alloc();
        break;
    case 0x1c:
    case 0x1d:
        *frame_storage = gquic_frame_connection_close_alloc();
        break;
    default:
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_FRAME);
    }
    if (*frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_FRAME_INIT(*frame_storage);
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_DESRIALIZE(*frame_storage, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

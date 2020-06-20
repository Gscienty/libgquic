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
#include "log.h"
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
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_ping_alloc((gquic_frame_ping_t **) frame_storage));
        break;
    case 0x02:
    case 0x03:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_ack_alloc((gquic_frame_ack_t **) frame_storage)); // TODO ack delay exponent
        break;
    case 0x04:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_reset_stream_alloc((gquic_frame_reset_stream_t **) frame_storage));
        break;
    case 0x05:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_stop_sending_alloc((gquic_frame_stop_sending_t **) frame_storage));
        break;
    case 0x06:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_crypto_alloc((gquic_frame_crypto_t **) frame_storage));
        break;
    case 0x07:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_new_token_alloc((gquic_frame_new_token_t **) frame_storage));
        break;
    case 0x10:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_max_data_alloc((gquic_frame_max_data_t **) frame_storage));
        break;
    case 0x11:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_max_stream_data_alloc((gquic_frame_max_stream_data_t **) frame_storage));
        break;
    case 0x12:
    case 0x13:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_max_streams_alloc((gquic_frame_max_streams_t **) frame_storage));
        break;
    case 0x14:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_data_blocked_alloc((gquic_frame_data_blocked_t **) frame_storage));
        break;
    case 0x15:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_stream_data_blocked_alloc((gquic_frame_stream_data_blocked_t **) frame_storage));
        break;
    case 0x16:
    case 0x17:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_streams_blocked_alloc((gquic_frame_streams_blocked_t **) frame_storage));
        break;
    case 0x18:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_new_connection_id_alloc((gquic_frame_new_connection_id_t **) frame_storage));
        break;
    case 0x19:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_retire_connection_id_alloc((gquic_frame_retire_connection_id_t **) frame_storage));
        break;
    case 0x1a:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_path_challenge_alloc((gquic_frame_path_challenge_t **) frame_storage));
        break;
    case 0x1b:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_path_response_alloc((gquic_frame_path_response_t **) frame_storage));
        break;
    case 0x1c:
    case 0x1d:
        GQUIC_ASSERT_FAST_RETURN(gquic_frame_connection_close_alloc((gquic_frame_connection_close_t **) frame_storage));
        break;
    default:
        GQUIC_LOG(GQUIC_LOG_ERROR, "received invalid frame type: (%02x)", GQUIC_STR_FIRST_BYTE(reader));
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INVALID_FRAME);
    }
    if (*frame_storage == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_INTERNAL_ERROR);
    }
    GQUIC_FRAME_INIT(*frame_storage);
    GQUIC_ASSERT_FAST_RETURN(GQUIC_FRAME_DESRIALIZE(*frame_storage, reader));

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

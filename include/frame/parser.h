/* include/frame/parser.h 解析frame定义
 * 该模块用于反序列化frame
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_PARSER_H
#define _LIBGQUIC_FRAME_PARSER_H

#include "util/str.h"
#include "exception.h"

typedef struct gquic_frame_parser_s gquic_frame_parser_t;
struct gquic_frame_parser_s {
    int ack_delay_exponent;
};

/**
 * 初始化frame parser
 * 
 * @param parser: parser
 * 
 * @return: exception
 */
gquic_exception_t gquic_frame_parser_init(gquic_frame_parser_t *const parser);

/**
 * 从reader中解析frame
 *
 * @param parser: parser
 * @param reader: reader
 * @param enc_lv: 加密级别
 *
 * @return frame_storage: frame
 * @return: exception
 */
gquic_exception_t gquic_frame_parser_next(void **const frame_storage,
                                          gquic_frame_parser_t *const parser, gquic_reader_str_t *const reader, const u_int8_t enc_lv);

#endif

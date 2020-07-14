/* include/handshake/initial_aead.h 初始化AEAD加密模块辅助部分声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_HANDSHAKE_INITIAL_AEAD_H
#define _LIBGQUIC_HANDSHAKE_INITIAL_AEAD_H

#include "handshake/header_protector.h"
#include "handshake/aead.h"
#include "exception.h"
#include <stdbool.h>

/**
 * 将加密/解密模块进行初始化
 *
 * @param sealer: 加密模块
 * @param opener: 解密模块
 * @param conn_id: connection id
 * @param is_client: 是否为客户端
 *
 * @return: exception
 */
gquic_exception_t gquic_handshake_initial_aead_init(gquic_common_long_header_sealer_t *const sealer,
                                                    gquic_common_long_header_opener_t *const opener,
                                                    const gquic_str_t *const conn_id,
                                                    const bool is_client);

#endif

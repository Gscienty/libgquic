/* include/tls/prf.h 通过签名算法获取OpenSSL MD
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_PRF_H
#define _LIBGQUIC_TLS_PRF_H

#include "exception.h"
#include <openssl/evp.h>
#include <sys/types.h>

/**
 * 通过签名算法获取OpenSSL MD
 *
 * @param sigalg: 签名算法
 *
 * @return hash: OpenSSL MD
 * @return: exception
 */
gquic_exception_t gquic_tls_hash_from_sigalg(const EVP_MD **const hash, u_int16_t sigalg);

#endif

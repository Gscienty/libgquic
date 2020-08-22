/* include/tls/auth.h TLS 认证过程
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_AUTH_H
#define _LIBGQUIC_TLS_AUTH_H

#include "util/list.h"
#include "util/str.h"
#include "tls/cipher_suite.h"
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

/**
 * 从对端与本端支持的签名协议中选择一个签名协议
 *
 * @param pkey: 公钥
 * @param peer_sigalgs: 对端支持的签名协议
 * @param self_sigalgs: 本端支持的签名协议
 * @param tls_ver: TLS版本
 *
 * @return sigalg: 签名算法
 * @return sig_type: 签名类型
 * @return hash: 哈希算法
 * @return: exception
 */
gquic_exception_t gquic_tls_selected_sigalg(u_int16_t *const sigalg, u_int8_t *const sig_type, const EVP_MD **const hash,
                                            const EVP_PKEY *const pkey,
                                            const gquic_list_t *const peer_sigalgs, const gquic_list_t *const self_sigalgs,
                                            const u_int16_t tls_ver);

/**
 * 验证握手阶段的签名
 *
 * @param hash: 哈希算法
 * @param pubkey: 公钥
 * @param sign: 本端计算的签名
 * @param sig: 对端计算的签名
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_verify_handshake_sign(const EVP_MD *const hash, EVP_PKEY *const pubkey, const gquic_str_t *sign, const gquic_str_t *sig);

/**
 * 计算签名
 *
 * @param sig_algo: 签名哈希算法
 * @param cnt: 标签
 * @param mac: mac过的签名部分
 *
 * @return ret: 签名
 * @return: exception
 */
gquic_exception_t gquic_tls_signed_msg(gquic_str_t *const ret, const EVP_MD *const sig_algo, const gquic_str_t *const cnt, gquic_tls_mac_t *const mac);

/**
 * 构造签名公钥
 *
 * @param sig_type: 签名类型
 * @param pubkey_s: 字节串公钥
 *
 * @return pubkey: 公钥
 * @return: exception
 */
gquic_exception_t gquic_tls_sig_pubkey(EVP_PKEY **const pubkey, const u_int8_t sig_type, const gquic_str_t *const pubkey_s);

/**
 * 从X509证书中获取签名公钥
 *
 * @param sig_type: 签名类型
 * @param x509: X509证书
 *
 * @return pubkey: 公钥
 * @return: exception
 */
gquic_exception_t gquic_tls_sig_pubkey_from_x509(EVP_PKEY **const pubkey, const u_int8_t sig_type, X509 *const x509);

/**
 * 从PKCS12证书中获取签名算法
 *
 * @param sigalgs: 待填充的签名算法列表
 * @param p12: PKCS12
 *
 * @return: exception
 */
gquic_exception_t gquic_tls_sigalg_from_cert(gquic_list_t *const sigalgs, PKCS12 *const p12);

#endif

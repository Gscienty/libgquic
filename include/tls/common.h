/* include/tls/common.h TLS 常量定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_TLS_COMMON_H
#define _LIBGQUIC_TLS_COMMON_H

#include "util/list.h"
#include "util/str.h"
#include "log.h"
#include <stdbool.h>

#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_HELLO_REQ 0x00
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLIENT_HELLO 0x01
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_SERVER_HELLO 0x02
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEW_SESS_TICKET 0x04
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_END_OF_EARLY_DATA 0x05
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_ENCRYPTED_EXTS 0x08
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT 0x0b
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_KEY_EXCHANGE 0x0c
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_REQ 0x0d
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_SER_HELLO_DONE 0x0e
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_VERIFY 0x0f
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CLI_KEY_EXCHANGE 0x10
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_FINISHED 0x14
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_CERT_STATUS 0x16
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_KEY_UPDATE 0x18
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_NEXT_PROTO 0x43
#define GQUIC_TLS_HANDSHAKE_MSG_TYPE_MSG_HASH 0xfe

#define GQUIC_TLS_EXTENSION_SERVER_NAME 0x00
#define GQUIC_TLS_EXTENSION_STATUS_REQUEST 0x05
#define GQUIC_TLS_EXTENSION_SUPPORTED_CURVES 0x0a   
#define GQUIC_TLS_EXTENSION_SUPPORTED_POINTS 0x0b
#define GQUIC_TLS_EXTENSION_SIGN_ALGOS 0x0d
#define GQUIC_TLS_EXTENSION_ALPN 0x10
#define GQUIC_TLS_EXTENSION_SCT 0x12
#define GQUIC_TLS_EXTENSION_SESS_TICKET 0x23
#define GQUIC_TLS_EXTENSION_PRE_SHARED_KEY 0x29
#define GQUIC_TLS_EXTENSION_EARLY_DATA 0x2a
#define GQUIC_TLS_EXTENSION_SUPPORTED_VERSIONS 0x2b
#define GQUIC_TLS_EXTENSION_COOKIE 0x2c
#define GQUIC_TLS_EXTENSION_PSK_MODES 0x2d
#define GQUIC_TLS_EXTENSION_CERT_AUTHS 0x2f
#define GQUIC_TLS_EXTENSION_SIGN_ALGOS_CERT 0x32
#define GQUIC_TLS_EXTENSION_KEY_SHARE 0x33
#define GQUIC_TLS_EXTENSION_NEXT_PROTO_NEG 0x3374
#define GQUIC_TLS_EXTENSION_RENEGOTIATION_INFO 0xff01
#define GQUIC_TLS_EXTENSION_QUIC 0xffa5

#define GQUIC_TLS_CERT_STATUS_TYPE_OCSP 0x01

#define GQUIC_TLS_VERSION_10 0x0301
#define GQUIC_TLS_VERSION_11 0x0302
#define GQUIC_TLS_VERSION_12 0x0303
#define GQUIC_TLS_VERSION_13 0x0304

#define GQUIC_TLS_RECORD_TYPE_CHANGE_CIPHER_SEPC 0x14
#define GQUIC_TLS_RECORD_TYPE_ALERT 0x15
#define GQUIC_TLS_RECORD_TYPE_HANDSHAKE 0x16
#define GQUIC_TLS_RECORD_TYPE_APP_DATA 0x17

#define GQUIC_TLS_CURVE_P256 0x17
#define GQUIC_TLS_CURVE_P384 0x18
#define GQUIC_TLS_CURVE_P521 0x19
#define GQUIC_TLS_CURVE_X25519 0x1d

#define GQUIC_SIGALG_PKCS1_SHA1 0x0201
#define GQUIC_SIGALG_PKCS1_SHA256 0x0401
#define GQUIC_SIGALG_PKCS1_SHA384 0x0501
#define GQUIC_SIGALG_PKCS1_SHA512 0x0601
#define GQUIC_SIGALG_PSS_SHA256 0x0804
#define GQUIC_SIGALG_PSS_SHA384 0x0805
#define GQUIC_SIGALG_PSS_SHA512 0x0806
#define GQUIC_SIGALG_ECDSA_SHA1 0x0203
#define GQUIC_SIGALG_ECDSA_P256_SHA256 0x0403
#define GQUIC_SIGALG_ECDSA_P384_SHA384 0x0503
#define GQUIC_SIGALG_ECDSA_P512_SHA512 0x0603
#define GQUIC_SIGALG_ED25519 0x0807

#define GQUIC_SIG_PKCS1V15 0x00
#define GQUIC_SIG_RSAPSS 0x01
#define GQUIC_SIG_ECDSA 0x02
#define GQUIC_SIG_ED25519 0x03

#define GQUIC_MAX_PLAINTEXT 16384
#define GQUIC_RECORD_SIZE_BOOST_THRESHOLD 131072
#define GQUIC_MSS_EST 1208

#define GQUIC_ENC_LV_INITIAL 1
#define GQUIC_ENC_LV_HANDSHAKE 2
#define GQUIC_ENC_LV_1RTT 3
#define GQUIC_ENC_LV_APP 4

const char *gquic_enc_lv_to_string_inner(const int enc_lv);
#if LOG
#define gquic_enc_lv_to_string(enc_lv) gquic_enc_lv_to_string_inner(enc_lv)
#else
#define gquic_enc_lv_to_string(enc_lv)
#endif

#define GQUIC_CLI_AUTH_REQ 0x01
#define GQUIC_CLI_AUTH_REQ_ANY 0x02
#define GQUIC_CLI_AUTH_VERIFY_IF_GIVEN 0x04
#define GQUIC_CLI_AUTH_REQ_VERIFY 0x08

typedef struct gquic_tls_key_share_s gquic_tls_key_share_t;
struct gquic_tls_key_share_s {
    u_int16_t group;
    gquic_str_t data;
};

typedef struct gquic_tls_extension_s gquic_tls_extension_t;
struct gquic_tls_extension_s {
    u_int16_t type;
    gquic_str_t data;
};

typedef struct gquic_tls_psk_identity_s gquic_tls_psk_identity_t;
struct gquic_tls_psk_identity_s {
    gquic_str_t label;
    u_int32_t obfuscated_ticket_age;
};

typedef struct gquic_tls_config_s gquic_tls_config_t;

const gquic_str_t *gquic_tls_hello_retry_request_random();
bool gquic_tls_is_supported_sigalg(const u_int16_t sigalg, const gquic_list_t *const sigalgs);
u_int8_t gquic_tls_sig_from_sigalg(const u_int16_t sigalg);
bool gquic_tls_requires_cli_cert(u_int8_t c);

#endif

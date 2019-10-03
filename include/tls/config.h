#ifndef _LIBGQUIC_TLS_CONFIG_H
#define _LIBGQUIC_TLS_CONFIG_H

#include <time.h>
#include <openssl/x509.h>
#include <sys/types.h>
#include "util/list.h"
#include "util/rbtree.h"
#include "util/str.h"

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


typedef uint16_t gquic_curve_id_t;

typedef struct gquic_tls_key_share_s gquic_tls_key_share_t;
struct gquic_tls_key_share_s {
    gquic_curve_id_t group;
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
struct gquic_tls_config_s {
    time_t epoch;
    gquic_list_t certs;
    gquic_rbtree_t map_certs;
    X509 *cli_ca;
    X509 *ser_ca;
    gquic_list_t next_protos;
    gquic_str_t ser_name;
    int insecure_skiy_verify;
    gquic_list_t cipher_suites;
    int ser_perfer_cipher_suite;
    int sess_ticket_disabled;
    u_int8_t sess_ticket_key[32];
    u_int16_t min_v;
    u_int16_t max_v;
    int dynamic_record_sizing_disabled;
    gquic_list_t sess_ticket_keys;
    int renegotiation;
    gquic_list_t curve_perfers;
};

typedef struct gquic_tls_ticket_key_s gquic_tls_ticket_key_t;
struct gquic_tls_ticket_key_s {
    u_int8_t name[16];
    u_int8_t aes_key[16];
    u_int8_t hmac_key[16];
};

int gquic_tls_ticket_key_deserialize(gquic_tls_ticket_key_t *ticket_key, const void *buf, const size_t size);

int gquic_tls_config_supported_versions(gquic_list_t *ret, const gquic_tls_config_t *cfg, int is_client);

int gquic_tls_config_curve_preferences(gquic_list_t *ret);

#endif

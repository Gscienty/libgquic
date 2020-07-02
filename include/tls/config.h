#ifndef _LIBGQUIC_TLS_CONFIG_H
#define _LIBGQUIC_TLS_CONFIG_H

#include "util/list.h"
#include "util/rbtree.h"
#include "util/str.h"
#include "tls/client_sess_state.h"
#include "tls/cert_req_msg.h"
#include "tls/common.h"
#include "tls/cipher_suite.h"
#include <time.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <sys/types.h>

typedef struct gquic_tls_record_layer_s gquic_tls_record_layer_t;
struct gquic_tls_record_layer_s {
    void *self;
    int (*set_rkey) (void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
    int (*set_wkey) (void *const, const u_int8_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
    int (*read_handshake_msg) (gquic_str_t *const, void *const);
    int (*write_record) (size_t *const, void *const, const gquic_str_t *const);
    int (*send_alert) (void *const, const u_int8_t);
};

int gquic_tls_record_layer_init(gquic_tls_record_layer_t *const record_layer);

struct gquic_tls_config_s {
    time_t epoch;
    gquic_list_t certs;
    gquic_rbtree_t *map_certs;
    gquic_str_t cli_ca;
    gquic_str_t ser_ca;
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
    gquic_tls_client_sess_cache_t *cli_sess_cache;
    void *ext_self;
    int (*extensions) (gquic_list_t *const, void *const, const u_int8_t);
    int (*received_extensions) (void *const, const u_int8_t, gquic_list_t *const);
    int (*verify_peer_certs) (const gquic_list_t *const, const gquic_list_t *const);
    int (*get_ser_cert) (PKCS12 **const, const gquic_tls_client_hello_msg_t *const);
    int (*get_cli_cert) (PKCS12 **const, const gquic_tls_cert_req_msg_t *const);
    gquic_tls_record_layer_t alt_record;
    int enforce_next_proto_selection;
    u_int8_t cli_auth;
};

#define GQUIC_TLS_CONFIG_GET_SER_CERT(cert, config, chello) \
    ((config)->get_ser_cert == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (config)->get_ser_cert(cert, chello))

#define GQUIC_TLS_CONFIG_GET_CLI_CERT(cert, config, cert_req) \
    ((config)->get_cli_cert == NULL \
     ? GQUIC_EXCEPTION_NOT_IMPLEMENTED \
     : (config)->get_cli_cert(cert, cert_req))

typedef struct gquic_tls_ticket_key_s gquic_tls_ticket_key_t;
struct gquic_tls_ticket_key_s {
    u_int8_t name[16];
    u_int8_t aes_key[16];
    u_int8_t hmac_key[16];
};

int gquic_tls_config_init(gquic_tls_config_t *const cfg);
// TODO config release
int gquic_tls_config_default(gquic_tls_config_t **const cfg);
int gquic_tls_config_supported_versions(gquic_list_t *ret, const gquic_tls_config_t *cfg, int is_client);
int gquic_tls_config_curve_preferences(gquic_list_t *ret);

int gquic_tls_ticket_key_deserialize(gquic_tls_ticket_key_t *ticket_key, const void *buf, const size_t size);
int gquic_tls_sig_trans(u_int8_t *const sig, const u_int16_t sigsche);
int gquic_tls_supported_sigalgs_tls12(gquic_list_t *const sigsches);

#endif

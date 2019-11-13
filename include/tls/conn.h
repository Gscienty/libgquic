#ifndef _LIBGQUIC_TLS_CONN_H
#define _LIBGQUIC_TLS_CONN_H

#include "tls/common.h"
#include "tls/config.h"
#include "tls/client_sess_state.h"
#include "tls/client_hello_msg.h"
#include "tls/cipher_suite.h"
#include "util/str.h"
#include "util/list.h"
#include "net/addr.h"
#include <sys/types.h>
#include <stdatomic.h>

typedef struct gquic_tls_half_conn_s gquic_tls_half_conn_t;
struct gquic_tls_half_conn_s {
    u_int16_t ver;
    gquic_tls_suite_t suite;
    gquic_str_t seq;
    gquic_str_t addata;
    gquic_tls_suite_t next_suite;
    gquic_str_t traffic_sec;
    void *set_key_self;
    int (*set_key) (void *const, const u_int16_t, const gquic_tls_cipher_suite_t *const, const gquic_str_t *const);
};

int gquic_tls_half_conn_init(gquic_tls_half_conn_t *const half_conn);
int gquic_tls_half_conn_encrypt(gquic_str_t *const ret,
                                gquic_tls_half_conn_t *const half_conn,
                                const gquic_str_t *const record,
                                const gquic_str_t *const payload);
int gquic_tls_half_conn_decrypt(gquic_str_t *const ret,
                                u_int8_t *const record_type,
                                gquic_tls_half_conn_t *const half_conn,
                                const gquic_str_t *const record);
int gquic_tls_half_conn_set_key(gquic_tls_half_conn_t *const half_conn,
                                const u_int16_t enc_lv,
                                const gquic_tls_cipher_suite_t *const cipher_suite,
                                const gquic_str_t *const secret);
int gquic_tls_half_conn_set_traffic_sec(gquic_tls_half_conn_t *const half_conn,
                                        const gquic_tls_cipher_suite_t *const cipher_suite,
                                        const gquic_str_t *const secret,
                                        int is_read);

typedef struct gquic_tls_conn_s gquic_tls_conn_t;
struct gquic_tls_conn_s {
    const gquic_net_addr_t *addr;
    gquic_tls_config_t *cfg;
    int is_client;
    _Atomic(u_int32_t) handshake_status;
    u_int16_t ver;
    int have_vers;
    int handshakes;
    int did_resume;
    u_int16_t cipher_suite;
    gquic_str_t ocsp_resp;
    gquic_list_t scts;
    gquic_list_t peer_certs;
    gquic_list_t verified_chains;
    gquic_str_t ser_name;
    int sec_renegortiation;
    gquic_tls_ekm_t ekm;
    gquic_str_t resumption_sec;
    int cli_finished_is_first;
    gquic_tls_half_conn_t in;
    gquic_tls_half_conn_t out;
    u_int64_t sent_size;
    u_int64_t sent_pkg_count;
    int buffering;
    gquic_str_t cli_proto;
    int cli_proto_fallback;
};

int gquic_tls_conn_init(gquic_tls_conn_t *const conn,
                        const gquic_net_addr_t *const addr,
                        gquic_tls_config_t *const cfg);

int gquic_tls_conn_load_session(gquic_str_t *const cache_key,
                                gquic_tls_client_sess_state_t **const sess,
                                gquic_str_t *const early_sec,
                                gquic_str_t *const binder_key,
                                const gquic_tls_conn_t *const conn,
                                gquic_tls_client_hello_msg_t *const hello);

int gquic_tls_conn_write_max_write_size(size_t *const ret, const gquic_tls_conn_t *const conn, const u_int8_t record_type);
int gquic_tls_conn_set_alt_record(gquic_tls_conn_t *const conn);
int gquic_tls_conn_write_record(size_t *const len, gquic_tls_conn_t *const conn, u_int8_t record_type, const gquic_str_t *const data);
int gquic_tls_conn_read_handshake(u_int8_t *const handshake_type, void **const msg, gquic_tls_conn_t *const conn);
int gquic_tls_conn_send_alert(gquic_tls_conn_t *const conn, u_int8_t alert);
int gquic_tls_conn_verify_ser_cert(gquic_tls_conn_t *const conn, const gquic_list_t *const certs);

#endif

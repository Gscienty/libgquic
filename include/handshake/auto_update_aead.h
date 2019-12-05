#ifndef _LIBGQUIC_HANDSHAKE_AUTO_UPDATE_AEAD_H
#define _LIBGQUIC_HANDSHAKE_AUTO_UPDATE_AEAD_H

#include "tls/cipher_suite.h"
#include "util/time.h"
#include "util/rtt.h"
#include "handshake/header_protector.h"

typedef struct gquic_auto_update_aead_s gquic_auto_update_aead_t;
struct gquic_auto_update_aead_s {
    const gquic_tls_cipher_suite_t *suite;
    u_int64_t times;
    u_int64_t last_ack_pn;
    u_int64_t update_interval;

    struct timeval prev_recv_aead_expire;
    gquic_tls_aead_t prev_recv_aead;

    u_int64_t cur_key_first_recv_pn;
    u_int64_t cur_key_first_sent_pn;
    u_int64_t cur_key_num_recv;
    u_int64_t cur_key_num_sent;

    gquic_tls_aead_t recv_aead;
    gquic_tls_aead_t send_aead;

    gquic_tls_aead_t next_recv_aead;
    gquic_tls_aead_t next_send_aead;

    gquic_str_t next_recv_traffic_sec;
    gquic_str_t next_send_traffic_sec;

    gquic_header_protector_t header_enc;
    gquic_header_protector_t header_dec;

    const gquic_rtt_t *rtt;

    gquic_str_t nonce_buf;
};

int gquic_auto_update_aead_init(gquic_auto_update_aead_t *const aead);
int gquic_auto_update_aead_roll(gquic_auto_update_aead_t *const aead, const struct timeval *const now);
int gquic_auto_update_aead_set_rkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec);
int gquic_auto_update_aead_set_wkey(gquic_auto_update_aead_t *const aead,
                                    const gquic_tls_cipher_suite_t *const suite,
                                    const gquic_str_t *const traffic_sec);
int gquic_auto_update_aead_open(gquic_str_t *const plain_text,
                                gquic_auto_update_aead_t *const aead,
                                const struct timeval *const recv_time,
                                const u_int64_t pn,
                                int kp,
                                const gquic_str_t *const tag,
                                const gquic_str_t *const cipher_text,
                                const gquic_str_t *const addata);
int gquic_auto_update_aead_seal(gquic_str_t *const tag,
                                gquic_str_t *const cipher_text,
                                gquic_auto_update_aead_t *const aead,
                                const u_int64_t pn,
                                const gquic_str_t *const plain_text,
                                const gquic_str_t *const addata);

#endif

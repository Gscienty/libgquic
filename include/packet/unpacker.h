#ifndef _LIBGQUIC_PACKET_UNPACKER_H
#define _LIBGQUIC_PACKET_UNPACKER_H

#include "handshake/establish.h"
#include "packet/header.h"
#include <sys/types.h>

typedef struct gquic_unpacked_packet_payload_s gquic_unpacked_packet_payload_t;
struct gquic_unpacked_packet_payload_s {
    struct {
        int is_1rtt;
        void *self;
        union {
            int (*cb) (gquic_str_t *const, void *const, const u_int64_t, const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
            int (*one_rtt_cb) (gquic_str_t *const, void *const, const u_int64_t, const u_int64_t, const int, const gquic_str_t *const, const gquic_str_t *const, const gquic_str_t *const);
        } cb;
    } opener;
    const gquic_str_t *data;
    gquic_header_protector_t *header_opener;
    u_int64_t recv_time;
};

#define GQUIC_UNPACKED_PACKET_PAYLOAD_OPEN(plain_text, payload, recv_time, pn, kp, tag, cipher_text, addata) \
    ((payload)->opener.is_1rtt \
     ? ((payload)->opener.cb.one_rtt_cb((plain_text), (payload)->opener.self, (recv_time), (pn), (kp), (tag), (cipher_text), (addata)))\
     : ((payload)->opener.cb.cb((plain_text), (payload)->opener.self, (pn), (tag), (cipher_text), (addata))))

int gquic_unpacked_packet_payload_init(gquic_unpacked_packet_payload_t *const payload);

typedef struct gquic_unpacked_packet_s gquic_unpacked_packet_t;
struct gquic_unpacked_packet_s {
    int valid;
    u_int64_t pn;
    gquic_packet_header_t hdr;
    u_int8_t enc_lv;
    gquic_str_t data;
};

int gquic_unpacked_packet_init(gquic_unpacked_packet_t *const unpacked_packet);
int gquic_unpacked_packet_dtor(gquic_unpacked_packet_t *const unpacked_packet);

typedef struct gquic_packet_unpacker_s gquic_packet_unpacker_t;
struct gquic_packet_unpacker_s {
    gquic_handshake_establish_t *est;
    u_int64_t largest_recv_pn;
};

int gquic_packet_unpacker_init(gquic_packet_unpacker_t *const unpacker);
int gquic_packet_unpacker_ctor(gquic_packet_unpacker_t *const unpacker, gquic_handshake_establish_t *const est);
int gquic_packet_unpacker_unpack(gquic_unpacked_packet_t *const unpacked_packet,
                                 gquic_packet_unpacker_t *const unpacker,
                                 const gquic_str_t *const data,
                                 const u_int64_t recv_time);

#endif

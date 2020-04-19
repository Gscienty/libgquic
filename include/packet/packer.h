#ifndef _LIBGQUIC_PACKET_PACKER_H
#define _LIBGQUIC_PACKET_PACKER_H

#include "packet/header.h"
#include "packet/packet_pool.h"
#include "packet/packet.h"
#include "packet/retransmission_queue.h"
#include "packet/received_packet_handler.h"
#include "packet/sent_packet_handler.h"
#include "frame/ack.h"
#include "frame/crypto.h"
#include "frame/connection_close.h"
#include "handshake/establish.h"
#include "streams/framer.h"
#include "streams/crypto.h"
#include "util/list.h"

typedef struct gquic_packed_packet_s gquic_packed_packet_t;
struct gquic_packed_packet_s {
    int valid;
    gquic_packet_header_t hdr;
    gquic_str_t raw;
    gquic_frame_ack_t *ack;
    gquic_list_t *frames;
    gquic_packet_buffer_t *buffer;
};

int gquic_packed_packet_init(gquic_packed_packet_t *const packed_packet);
int gquic_packed_packet_dtor(gquic_packed_packet_t *const packed_packet);
int gquic_packed_packet_dtor_without_frames(gquic_packed_packet_t *const packed_packet);
u_int8_t gquic_packed_packet_enc_lv(const gquic_packed_packet_t *const packed_packet);
int gquic_packed_packet_is_ack_eliciting(gquic_packed_packet_t *const packed_packet);
int gquic_packed_packet_get_ack_packet(gquic_packet_t *const packet,
                                       gquic_packed_packet_t *const packed_packet,
                                       gquic_retransmission_queue_t *const queue);

typedef struct gquic_packed_packet_payload_s gquic_packed_packet_payload_t;
struct gquic_packed_packet_payload_s {
    gquic_list_t *frames; /* void * */
    gquic_frame_ack_t *ack;
    u_int64_t len;

    struct {
        void *self;
        int (*cb)(gquic_str_t *const,
                  gquic_str_t *const,
                  void *const,
                  const u_int64_t,
                  const gquic_str_t *const,
                  const gquic_str_t *const);
    } sealer;
    gquic_header_protector_t *header_sealer;

    gquic_packet_header_t hdr;
    u_int8_t enc_lv;
};

int gquic_packed_packet_payload_init(gquic_packed_packet_payload_t *const payload);
int gquic_packed_packet_payload_dtor(gquic_packed_packet_payload_t *const payload);

#define GQUIC_PACKED_PACKET_PAYLOAD_SEAL(tag, cipher_text, payload, pn, plain_text, addata) \
    ((payload)->sealer.cb((tag), (cipher_text), (payload)->sealer.self, (pn), (plain_text), (addata)))

typedef struct gquic_packet_packer_s gquic_packet_packer_t;
struct gquic_packet_packer_s {
    gquic_str_t conn_id;
    struct {
        void *self;
        int (*cb) (gquic_str_t *const, void *const);
    } get_conn_id;

    int is_client;
    gquic_handshake_establish_t *est;

    int droped_initial;
    int droped_handshake;

    gquic_crypto_stream_t *initial_stream;
    gquic_crypto_stream_t *handshake_stream;

    gquic_str_t token;

    gquic_packet_sent_packet_handler_t *pn_gen;
    gquic_framer_t *framer;

    gquic_packet_received_packet_handlers_t *acks;
    gquic_retransmission_queue_t *retransmission_queue;

    u_int64_t max_packet_size;
    int non_ack_eliciting_acks_count;
};

int gquic_packet_packer_init(gquic_packet_packer_t *const packer);
int gquic_packet_packer_ctor(gquic_packet_packer_t *const packer,
                             const gquic_str_t *const src_id,
                             void *const get_conn_id_self,
                             int (*get_conn_id_cb) (gquic_str_t *const, void *const),
                             gquic_crypto_stream_t *const initial_stream,
                             gquic_crypto_stream_t *const handshake_stream,
                             gquic_packet_sent_packet_handler_t *const pn_gen,
                             gquic_retransmission_queue_t *const retransmission_queue,
                             const u_int64_t max_packet_size,
                             gquic_handshake_establish_t *const est,
                             gquic_framer_t *const framer,
                             gquic_packet_received_packet_handlers_t *acks,
                             const int is_client);
int gquic_packet_packer_dtor(gquic_packet_packer_t *const packer);
int gquic_packet_packer_pack_conn_close(gquic_packed_packet_t *const packed_packet,
                                        gquic_packet_packer_t *const packer,
                                        const gquic_frame_connection_close_t *const conn_close);
int gquic_packet_packer_get_short_header(gquic_packet_header_t *const hdr, gquic_packet_packer_t *const packer, const int times);
int gquic_packet_packer_get_long_header(gquic_packet_header_t *const hdr, gquic_packet_packer_t *const packer, const u_int8_t enc_lv);
int gquic_packet_packer_pack(gquic_packed_packet_t *const packed_packet,
                             gquic_packet_packer_t *const packer,
                             gquic_packed_packet_payload_t *const payload);
int gquic_packet_packer_pack_with_padding(gquic_packed_packet_t *const packed_packet,
                                          gquic_packet_packer_t *const packer,
                                          gquic_packed_packet_payload_t *const payload,
                                          const u_int64_t padding_len);
int gquic_packet_packer_try_pack_ack_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_try_pack_initial_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_try_pack_handshake_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_try_pack_app_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_try_pack_crypto_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_try_pack_probe_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer, const u_int8_t enc_lv);
int gquic_packet_packer_pack_packet(gquic_packed_packet_t *const packed_packet, gquic_packet_packer_t *const packer);
int gquic_packet_packer_pack_crypto_packet(gquic_packed_packet_t *const packed_packet,
                                           gquic_packet_packer_t *const packer,
                                           gquic_packed_packet_payload_t *const payload,
                                           const int has_retransmission);


inline static int gquic_packet_packer_handshake_confirmed(gquic_packet_packer_t *const packer) {
    if (packer == NULL) {
        return 0;
    }
    return packer->droped_initial && packer->droped_handshake;
}

#define GQUIC_PACKET_PACKER_GET_CONN_ID(conn_id, packer) ((packer)->get_conn_id.cb((conn_id), (packer)->get_conn_id.self))

#endif

#ifndef _LIBGQUIC_STREAMS_CRYPTO_H
#define _LIBGQUIC_STREAMS_CRYPTO_H

#include "frame/frame_sorter.h"
#include "frame/crypto.h"
#include "streams/framer.h"
#include "util/str.h"

typedef struct gquic_crypto_stream_s gquic_crypto_stream_t;
struct gquic_crypto_stream_s {
    gquic_frame_sorter_t sorter;
    gquic_reader_str_t in_reader;
    gquic_str_t in_buf;

    u_int64_t highest_off;
    int finished;

    u_int64_t out_off;
    gquic_reader_str_t out_reader;
    gquic_str_t out_buf;
};

int gquic_crypto_stream_init(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_ctor(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_handle_crypto_frame(gquic_crypto_stream_t *const str, gquic_frame_crypto_t *const frame);
int gquic_crypto_stream_get_data(gquic_str_t *const data, gquic_crypto_stream_t *const str);
int gquic_crypto_stream_finish(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_write(gquic_crypto_stream_t *const str, gquic_writer_str_t *const data);
int gquic_crypto_stream_has_data(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_pop_crypto_frame(gquic_frame_crypto_t **frame_storage, gquic_crypto_stream_t *const str, const u_int64_t max_len);

typedef struct gquic_post_handshake_crypto_stream_s gquic_post_handshake_crypto_stream_t;
struct gquic_post_handshake_crypto_stream_s {
    gquic_crypto_stream_t stream;
    gquic_framer_t *framer;
};
int gquic_post_handshake_crypto_stream_init(gquic_post_handshake_crypto_stream_t *const str);
int gquic_post_handshake_crypto_ctor(gquic_post_handshake_crypto_stream_t *const str, gquic_framer_t *const frame);
int gquic_post_handshake_crypto_write(gquic_post_handshake_crypto_stream_t *const str, gquic_writer_str_t *const writer);

typedef struct gquic_crypto_stream_manager_s gquic_crypto_stream_manager_t;
struct gquic_crypto_stream_manager_s {
    struct {
        void *self;
        int (*cb) (void *const, const gquic_str_t *const, const u_int8_t);
    } handle_msg;

    gquic_crypto_stream_t *initial_stream;
    gquic_crypto_stream_t *handshake_stream;
    gquic_post_handshake_crypto_stream_t *one_rtt_stream;
};

#define GQUIC_CRYPTO_STREAM_MANAGER_HANDLE_MSG(manage, data, enc_lv) \
    ((manage)->handle_msg.cb((manage)->handle_msg.self, (data), (enc_lv)))

int gquic_crypto_stream_manager_init(gquic_crypto_stream_manager_t *const manager);
int gquic_crypto_stream_manager_ctor(gquic_crypto_stream_manager_t *const manager,
                                     void *handle_msg_self,
                                     int (*handle_msg_cb) (void *const, const gquic_str_t *const, const u_int8_t),
                                     gquic_crypto_stream_t *const initial_stream,
                                     gquic_crypto_stream_t *const handshake_stream,
                                     gquic_post_handshake_crypto_stream_t *const one_rtt_stream);
int gquic_crypto_stream_manager_handle_crypto_frame(int *const changed,
                                                    gquic_crypto_stream_manager_t *const manager,
                                                    gquic_frame_crypto_t *const frame,
                                                    const u_int8_t enc_lv);

#endif

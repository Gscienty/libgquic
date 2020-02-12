#ifndef _LIBGQUIC_STREAMS_CRYPTO_H
#define _LIBGQUIC_STREAMS_CRYPTO_H

#include "frame/frame_sorter.h"
#include "frame/crypto.h"
#include "util/str.h"

typedef struct gquic_crypto_stream_s gquic_crypto_stream_t;
struct gquic_crypto_stream_s {
    gquic_frame_sorter_t queue;
    gquic_reader_str_t reader;
    gquic_str_t msg_buf;

    u_int64_t highest_off;
    int finished;

    u_int64_t write_off;
    gquic_writer_str_t writer;
    gquic_str_t write_buf;
};

int gquic_crypto_stream_init(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_ctor(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_handle_crypto_frame(gquic_crypto_stream_t *const str, gquic_frame_crypto_t *const frame);
int gquic_crypto_stream_get_data(gquic_str_t *const data, gquic_crypto_stream_t *const str);
int gquic_crypto_stream_finish(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_write(gquic_crypto_stream_t *const str, const gquic_str_t *const data);
int gquic_crypto_stream_has_data(gquic_crypto_stream_t *const str);
int gquic_crypto_stream_pop_crypto_frame(gquic_frame_crypto_t **frame_storage, gquic_crypto_stream_t *const str, const u_int64_t max_len);

#endif

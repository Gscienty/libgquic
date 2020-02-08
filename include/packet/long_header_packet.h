#ifndef _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H
#define _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H

#include "packet_number.h"
#include "util/version.h"
#include "util/varint.h"

typedef struct gquic_packet_long_header_s gquic_packet_long_header_t;
struct gquic_packet_long_header_s {
    u_int8_t flag;
    gquic_version_t version;
    u_int8_t dcid_len;
    u_int8_t dcid[20];
    u_int8_t scid_len;
    u_int8_t scid[20];
};

typedef struct gquic_packet_initial_header_s gquic_packet_initial_header_t;
struct gquic_packet_initial_header_s {
    u_int64_t token_len;
    void *token;
    u_int64_t len;
    u_int64_t pn;
};

typedef struct gquic_packet_0rtt_header_s gquic_packet_0rtt_header_t;
struct gquic_packet_0rtt_header_s {
    u_int64_t len;
    u_int64_t pn;
};

typedef struct gquic_packet_handshake_header_s gquic_packet_handshake_header_t;
struct gquic_packet_handshake_header_s {
    u_int64_t len;
    u_int64_t pn;
};

typedef struct gquic_packet_retry_header_s gquic_packet_retry_header_t;
struct gquic_packet_retry_header_s {
    unsigned char odcid_len;
    unsigned char odcid[20];
};


#define GQUIC_LONG_HEADER_SPEC(h) ((void *) (((void *) (h)) + sizeof(gquic_packet_long_header_t)))
#define GQUIC_LONG_HEADER_COMMON(h) (*((gquic_packet_long_header_t *) (((void *) (h)) + sizeof(gquic_packet_long_header_t))))

gquic_packet_long_header_t *gquic_packet_long_header_alloc();
int gquic_packet_long_header_release(gquic_packet_long_header_t *const header);
size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *const header);
int gquic_packet_long_header_serialize(const gquic_packet_long_header_t *const header, gquic_writer_str_t *const writer);
int gquic_packet_long_header_deserialize(gquic_packet_long_header_t *const header, gquic_reader_str_t *const reader);

#define GQUIC_LONG_HEADER_INITIAL 0x01
#define GQUIC_LONG_HEADER_0RTT 0x02
#define GQUIC_LONG_HEADER_HANDSHAKE 0x03
#define GQUIC_LONG_HEADER_RETRY 0x04

u_int8_t gquic_packet_long_header_type(const gquic_packet_long_header_t *const header);

#endif

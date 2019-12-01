#ifndef _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H
#define _LIBGQUIC_PACKET_LONG_HEADER_PACKET_H

#include "packet_number.h"
#include "util/version.h"
#include "util/varint.h"

typedef struct gquic_packet_long_header_s gquic_packet_long_header_t;
struct gquic_packet_long_header_s {
    unsigned char flag;
    gquic_version_t version;
    unsigned char dcid_len;
    unsigned char dcid[20];
    unsigned char scid_len;
    unsigned char scid[20];
};

typedef struct gquic_packet_initial_header_s gquic_packet_initial_header_t;
struct gquic_packet_initial_header_s {
    gquic_varint_t token_len;
    void *token;
    gquic_varint_t len;
    gquic_packet_number_t pn;
};

typedef struct gquic_packet_0rtt_header_s gquic_packet_0rtt_header_t;
struct gquic_packet_0rtt_header_s {
    gquic_varint_t len;
    gquic_packet_number_t pn;
};

typedef struct gquic_packet_handshake_header_s gquic_packet_handshake_header_t;
struct gquic_packet_handshake_header_s {
    gquic_varint_t len;
    gquic_packet_number_t pn;
};

typedef struct gquic_packet_retry_header_s gquic_packet_retry_header_t;
struct gquic_packet_retry_header_s {
    unsigned char odcid_len;
    unsigned char odcid[20];
};

typedef void *gquic_long_header_spec_ptr_t;

#define GQUIC_LONG_HEADER_SPEC(h) ((gquic_long_header_spec_ptr_t) (((void *) (h)) + sizeof(gquic_packet_long_header_t)))
#define GQUIC_LONG_HEADER_COMMON(h) (*((gquic_packet_long_header_t *) (((void *) (h)) + sizeof(gquic_packet_long_header_t))))

gquic_packet_long_header_t *gquic_packet_long_header_alloc();
size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *);
ssize_t gquic_packet_long_header_serialize(const gquic_packet_long_header_t *, void *, const size_t);
ssize_t gquic_packet_long_header_deserialize(gquic_packet_long_header_t *, const void *, const size_t);

#endif

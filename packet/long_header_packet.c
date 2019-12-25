#include "packet/long_header_packet.h"
#include "util/big_endian.h"
#include <malloc.h>
#include <string.h>

#define __Max(x, y) ((x) > (y) ? (x) : (y))

static size_t gquic_packet_initial_header_size(const gquic_packet_initial_header_t *);
static size_t gquic_packet_0rtt_header_size(const gquic_packet_0rtt_header_t *);
static size_t gquic_packet_handshake_header_size(const gquic_packet_handshake_header_t *);
static size_t gquic_packet_retry_header_size(const gquic_packet_retry_header_t *);

static ssize_t gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *, void *, const size_t);
static ssize_t gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *, void *, const size_t);
static ssize_t gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *, void *, const size_t);
static ssize_t gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *, void *, const size_t);

static ssize_t gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *, const void *, const size_t);
static ssize_t gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *, const void *, const size_t);
static ssize_t gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *, const void *, const size_t);
static ssize_t gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *, const void *, const size_t);

const static size_t SUB_MAX_SIZE = __Max(
                                         __Max(sizeof(gquic_packet_0rtt_header_t),
                                               sizeof(gquic_packet_retry_header_t)),
                                         __Max(sizeof(gquic_packet_initial_header_t),
                                               sizeof(gquic_packet_handshake_header_t)));

gquic_packet_long_header_t *gquic_packet_long_header_alloc() {
    gquic_packet_long_header_t *header = malloc(sizeof(gquic_packet_long_header_t) + SUB_MAX_SIZE);
    if (header == NULL) {
        return NULL;
    }
    return header;
}

size_t gquic_packet_long_header_size(const gquic_packet_long_header_t *header) {
    if (header == NULL) {
        return 0;
    }
    size_t common = 1 + 4 + 1 + header->dcid_len + 1 + header->scid_len;
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        return common + gquic_packet_initial_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x01:
        return common + gquic_packet_0rtt_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x02:
        return common + gquic_packet_handshake_header_size(GQUIC_LONG_HEADER_SPEC(header));
    case 0x03:
        return common + gquic_packet_handshake_header_size(GQUIC_LONG_HEADER_SPEC(header));
    }
    return 0;
}

ssize_t gquic_packet_long_header_serialize(const gquic_packet_long_header_t *header, void *buf, const size_t size) {
    ssize_t serialize_len = 0;
    size_t off = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_packet_long_header_size(header) > size) {
        return -3;
    }
    ((unsigned char *) buf)[off++] = header->flag;
    gquic_big_endian_transfer(buf + off, &header->version, 4);
    off += 4;
    ((unsigned char *) buf)[off++] = header->dcid_len;
    memcpy(buf + off, header->dcid, header->dcid_len);
    off += header->dcid_len;
    ((unsigned char *) buf)[off++] = header->scid_len;
    memcpy(buf + off, header->scid, header->scid_len);
    off += header->scid_len;
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        serialize_len = gquic_packet_initial_header_serialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x01:
        serialize_len = gquic_packet_0rtt_header_serialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x02:
        serialize_len = gquic_packet_handshake_header_serialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x03:
        serialize_len = gquic_packet_handshake_header_serialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    }
    if (serialize_len <= 0) {
        return -4;
    }
    return off + serialize_len;
}

ssize_t gquic_packet_long_header_deserialize(gquic_packet_long_header_t *header, const void *buf, const size_t size) {
    ssize_t deserialize_len = 0;
    size_t off = 0;
    if (header == NULL) {
        return -1;
    }
    header->flag = ((unsigned char *) buf)[off++];
    gquic_big_endian_transfer(&header->version, buf + off, 4);
    off += 4;
    header->dcid_len = ((unsigned char *) buf)[off++];
    memcpy(&header->dcid, buf + off, header->dcid_len);
    off += header->dcid_len;
    header->scid_len = ((unsigned char *) buf)[off++];
    memcpy(&header->scid, buf + off, header->scid_len);
    off += header->scid_len;
    switch ((header->flag & 0x30) >> 4) {
    case 0x00:
        deserialize_len = gquic_packet_initial_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x01:
        deserialize_len = gquic_packet_0rtt_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x02:
        deserialize_len = gquic_packet_handshake_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    case 0x03:
        deserialize_len = gquic_packet_handshake_header_deserialize(GQUIC_LONG_HEADER_SPEC(header), buf + off, size - off);
        break;
    }
    if (deserialize_len <= 0) {
        return -4;
    }
    return off + deserialize_len;
}

static size_t gquic_packet_initial_header_size(const gquic_packet_initial_header_t *header) {
    if (header == NULL) {
        return 0;
    }
    return gquic_varint_size(&header->len)
        + gquic_varint_size(&header->token_len)
        + header->token_len
        + gquic_packet_number_size(header->pn);
}

static size_t gquic_packet_0rtt_header_size(const gquic_packet_0rtt_header_t *header) {
    return gquic_varint_size(&header->len)
        + gquic_packet_number_size(header->pn);
}

static size_t gquic_packet_handshake_header_size(const gquic_packet_handshake_header_t *header) {
    return gquic_varint_size(&header->len)
        + gquic_packet_number_size(header->pn);
}

static size_t gquic_packet_retry_header_size(const gquic_packet_retry_header_t *header) {
    return 1 + header->odcid_len;
}

static ssize_t gquic_packet_initial_header_serialize(const gquic_packet_initial_header_t *header, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_packet_initial_header_size(header) > size) {
        return -3;
    }
    serialize_len = gquic_varint_serialize(&header->token_len, buf + off, size - off);
    if (serialize_len <= 0) {
        return -4;
    }
    off += serialize_len;

    memcpy(buf + off, header->token, header->token_len);
    off += header->token_len;

    serialize_len = gquic_varint_serialize(&header->len, buf + off, size - off);
    if (serialize_len <= 0) {
        return -4;
    }
    off += serialize_len;
    gquic_big_endian_transfer(buf + off, &header->pn, gquic_packet_number_size(header->pn));
    return off + gquic_packet_number_size(header->pn);
}

static ssize_t gquic_packet_0rtt_header_serialize(const gquic_packet_0rtt_header_t *header, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_packet_0rtt_header_size(header) > size) {
        return -3;
    }
    serialize_len = gquic_varint_serialize(&header->len, buf + off, size - off);
    if (serialize_len <= 0) {
        return -4;
    }
    off += serialize_len;
    gquic_big_endian_transfer(buf + off, &header->pn, gquic_packet_number_size(header->pn));
    return off + gquic_packet_number_size(header->pn);
}

static ssize_t gquic_packet_handshake_header_serialize(const gquic_packet_handshake_header_t *header, void *buf, const size_t size) {
    size_t off = 0;
    ssize_t serialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_packet_handshake_header_size(header) > size) {
        return -3;
    }
    serialize_len = gquic_varint_serialize(&header->len, buf + off, size - off);
    if (serialize_len <= 0) {
        return -4;
    }
    off += serialize_len;
    gquic_big_endian_transfer(buf + off, &header->pn, gquic_packet_number_size(header->pn));
    return off + gquic_packet_number_size(header->pn);
}

static ssize_t gquic_packet_retry_header_serialize(const gquic_packet_retry_header_t *header, void *buf, const size_t size) {
    size_t off = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (gquic_packet_retry_header_size(header) > size) {
        return -3;
    }
    ((unsigned char *) buf)[off++] = header->odcid_len;
    memcpy(buf + off, header->odcid, header->odcid_len);
    return 1 + header->odcid_len;
}

static ssize_t gquic_packet_initial_header_deserialize(gquic_packet_initial_header_t *header, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    deserialize_len = gquic_varint_deserialize(&header->token_len, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -3;
    }
    off += deserialize_len;
    if (header->token_len > size - off) {
        return -3;
    }
    header->token = malloc(header->token_len);
    if (header->token == NULL) {
        return -3;
    }
    memcpy(header->token, buf + off, header->token_len);
    off += header->token_len;
    deserialize_len = gquic_varint_deserialize(&header->len, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -3;
    }
    off += deserialize_len;
    deserialize_len = gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
    if ((size_t) deserialize_len > size) {
        return -3;
    }
    header->pn = 0;
    if (gquic_big_endian_transfer(&header->pn, buf + off, deserialize_len) != 0) {
        return -3;
    }
    off += deserialize_len;
    return off;
}

static ssize_t gquic_packet_0rtt_header_deserialize(gquic_packet_0rtt_header_t *header, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    deserialize_len = gquic_varint_deserialize(&header->len, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -3;
    }
    off += deserialize_len;
    deserialize_len = gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
    if ((size_t) deserialize_len > size) {
        return -3;
    }
    header->pn = 0;
    if (gquic_big_endian_transfer(&header->pn, buf + off, deserialize_len) != 0) {
        return -3;
    }
    off += deserialize_len;
    return off;
}
static ssize_t gquic_packet_handshake_header_deserialize(gquic_packet_handshake_header_t *header, const void *buf, const size_t size) {
    size_t off = 0;
    ssize_t deserialize_len = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    deserialize_len = gquic_varint_deserialize(&header->len, buf + off, size - off);
    if (deserialize_len <= 0) {
        return -3;
    }
    off += deserialize_len;
    deserialize_len = gquic_packet_number_flag_to_size(GQUIC_LONG_HEADER_COMMON(header).flag);
    if ((size_t) deserialize_len > size) {
        return -3;
    }
    header->pn = 0;
    if (gquic_big_endian_transfer(&header->pn, buf + off, deserialize_len) != 0) {
        return -3;
    }
    off += deserialize_len;
    return off;
}

static ssize_t gquic_packet_retry_header_deserialize(gquic_packet_retry_header_t *header, const void *buf, const size_t size) {
    size_t off = 0;
    if (header == NULL) {
        return -1;
    }
    if (buf == NULL) {
        return -2;
    }
    if (1 > size) {
        return -3;
    }
    header->odcid_len = ((unsigned char *) buf)[off++];
    if (header->odcid_len > size - off) {
        return -3;
    }
    memcpy(header->odcid, buf + off, header->odcid_len);
    return off + header->odcid_len;
}


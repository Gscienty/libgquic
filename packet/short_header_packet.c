#include "packet/short_header_packet.h"
#include "util/big_endian.h"
#include <malloc.h>
#include <string.h>

gquic_packet_short_header_t *gquic_packet_short_header_alloc() {
    gquic_packet_short_header_t *header = malloc(sizeof(gquic_packet_short_header_t));
    if (header == NULL) {
        return NULL;
    }
    memset(header->dcid, 0, sizeof(header->dcid));
    header->dcid_len = 0;
    header->flag = 0;
    header->pn = 0;

    return header;
}

ssize_t gquic_packet_short_header_size(const gquic_packet_short_header_t *const header) {
    if (header == NULL) {
        return -1;
    }
    return 1 + header->dcid_len + (header->flag & 0x03) + 1;
}

ssize_t gquic_packet_short_header_serialize(const gquic_packet_short_header_t *const header, void *const buf, const size_t size) {
    size_t off = 0;
    if (header == NULL || buf == NULL) {
        return -1;
    }
    if ((size_t) gquic_packet_short_header_size(header) > size) {
        return -2;
    }
    ((u_int8_t *) buf)[off++] = header->flag;
    memcpy(buf + off, header->dcid, header->dcid_len);
    off += header->dcid_len;
    gquic_big_endian_transfer(buf + off, &header->pn, (header->flag & 0x03) + 1);
    off += (header->flag & 0x03) + 1;
    return off;
}

ssize_t gquic_packet_short_header_deserialize(gquic_packet_short_header_t *const header, const void *const buf, const size_t size) {
    (void) size;
    size_t off = 0;
    if (header == NULL || buf == NULL) {
        return -1;
    }
    header->flag = ((u_int8_t *) buf)[off++];
    memcpy(header->dcid, buf + off, header->dcid_len);
    off += header->dcid_len;
    gquic_big_endian_transfer(&header->pn, buf + off, (header->flag & 0x03) + 1);
    off += (header->flag & 0x03) + 1;
    return off;
}

#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include <sys/types.h>

size_t gquic_packet_number_size(const u_int64_t pn);
unsigned char gquic_packet_number_flag(const u_int64_t pn);
size_t gquic_packet_number_flag_to_size(const u_int8_t flag);

#endif

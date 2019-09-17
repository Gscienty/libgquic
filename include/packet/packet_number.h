#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include <unistd.h>

typedef unsigned long gquic_packet_number_t;

size_t gquic_packet_number_size(const gquic_packet_number_t pn);

unsigned char gquic_packet_number_flag(const gquic_packet_number_t pn);

size_t gquic_packet_number_flag_to_size(const unsigned char flag);

#endif

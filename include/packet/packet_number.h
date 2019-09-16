#ifndef _LIBGQUIC_PACKET_PACKET_NUMBER_H
#define _LIBGQUIC_PACKET_PACKET_NUMBER_H

#include <unistd.h>

typedef unsigned long gquic_packet_number_t;

size_t gquic_packet_number_size(const gquic_packet_number_t pn);

#endif

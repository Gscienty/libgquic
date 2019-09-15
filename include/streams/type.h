#ifndef _LIBGQUIC_STREAMS_TYPE_H
#define _LIBGQUIC_STREAMS_TYPE_H

#include "util/varint.h"

typedef gquic_util_varint_t gquic_stream_id_t;
typedef unsigned char gquic_stream_type_t;


#define GQUIC_STREAM_CLIENT_INITIATED 0x00
#define GQUIC_STREAM_SERVER_INITIATED 0x01

#define GQUIC_STREAM_BIDIRECTIONAL  0x00
#define GQUIC_STREAM_UNIDIRECTIONAL 0x02


#endif

#ifndef _LIBGQUIC_UTIL_BIG_ENDIAN_H
#define _LIBGQUIC_UTIL_BIG_ENDIAN_H

#include <unistd.h>

int gquic_big_endian_transfer(void *, const void *, const size_t);

#endif

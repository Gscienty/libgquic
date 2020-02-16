#ifndef _LIBGQUIC_UTIL_PN_H
#define _LIBGQUIC_UTIL_PN_H

#include <sys/types.h>

u_int64_t gquic_pn_decode(const int pn_len, const u_int64_t last_pn, const u_int64_t pn);

#endif

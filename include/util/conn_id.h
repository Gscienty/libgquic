#ifndef _LIBGQUIC_UTIL_CONN_ID_H
#define _LIBGQUIC_UTIL_CONN_ID_H

#include "util/str.h"

int gquic_conn_id_generate(gquic_str_t *const, const size_t);

#endif

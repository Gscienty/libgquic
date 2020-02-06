#ifndef _LIBGQUIC_UTIL_STREAM_ID_H
#define _LIBGQUIC_UTIL_STREAM_ID_H

#include <sys/types.h>

static inline u_int64_t gquic_stream_num_to_stream_id(const int is_bidi, const int is_client, const u_int64_t num) {
    u_int64_t first = 0;
    if (num == 0) {
        return (u_int64_t) -1;
    }
    if (is_bidi) {
        if (is_client) {
            first = 0;
        }
        else {
            first = 1;
        }
    }
    else {
        if (is_client) {
            first = 2;
        }
        else {
            first = 3;
        }
    }

    return first + 4 * (num  - 1);
}

static inline u_int64_t gquic_stream_id_to_stream_num(const u_int64_t id) {
    return id / 4 + 1;
}

static inline int gquic_stream_id_is_bidi(const u_int64_t id) {
    return id % 4 < 2;
}

static inline int gquic_stream_id_is_client(const u_int64_t id) {
    return id % 2 == 0;
}

#endif

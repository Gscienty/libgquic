#ifndef _LIBGQUIC_NET_ADDR_H
#define _LIBGQUIC_NET_ADDR_H

#include <arpa/inet.h>
#include <sys/un.h>
#include "util/str.h"

typedef struct gquic_net_addr_s gquic_net_addr_t;
struct gquic_net_addr_s {
    u_int32_t type;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
        struct sockaddr_un un;
    } addr;
};

int gquic_net_addr_init(gquic_net_addr_t *const addr);
int gquic_net_addr_to_str(const gquic_net_addr_t *const addr, gquic_str_t *const ret);
int gquic_net_str_to_addr_v4(gquic_net_addr_t *const addr, const char *const ip);

#endif

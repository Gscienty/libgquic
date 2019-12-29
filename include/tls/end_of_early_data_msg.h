#ifndef _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H
#define _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H

#include <sys/types.h>

typedef struct gquic_tls_end_of_early_data_msg_s gquic_tls_end_of_early_data_msg_t;
struct gquic_tls_end_of_early_data_msg_s { };

gquic_tls_end_of_early_data_msg_t *gquic_tls_end_of_early_data_msg_alloc();
#endif

#ifndef _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H
#define _LIBGQUIC_TLS_END_OF_EARLY_DATA_MSG_H

#include <sys/types.h>

typedef struct gquic_tls_end_of_early_data_msg_s gquic_tls_end_of_early_data_msg_t;
struct gquic_tls_end_of_early_data_msg_s { };

int gquic_tls_end_of_early_data_msg_init(gquic_tls_end_of_early_data_msg_t *msg);
int gquic_tls_end_of_early_data_msg_reset(gquic_tls_end_of_early_data_msg_t *msg);
ssize_t gquic_tls_end_of_early_data_msg_size(const gquic_tls_end_of_early_data_msg_t *msg);
ssize_t gquic_tls_end_of_early_data_msg_serialize(const gquic_tls_end_of_early_data_msg_t *msg, void *buf, const size_t size);
ssize_t gquic_tls_end_of_early_data_msg_deserialize(gquic_tls_end_of_early_data_msg_t *msg, const void *buf, const size_t size);


#endif

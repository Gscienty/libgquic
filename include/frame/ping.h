#ifndef _LIBGQUIC_FRAME_PING_H
#define _LIBGQUIC_FRAME_PING_H

typedef struct gquic_frame_ping_s gquic_frame_ping_t;
struct gquic_frame_ping_s { };

int gquic_frame_ping_alloc(gquic_frame_ping_t **const frame_storage);

#endif

#ifndef _LIBGQUIC_FRAME_HANDSAHKE_DONE_H
#define _LIBGQUIC_FRAME_HANDSAHKE_DONE_H

typedef struct gquic_frame_handshake_done_s gquic_frame_handshake_done_t;
struct gquic_frame_handshake_done_s { };

int gquic_frame_handshake_done_alloc(gquic_frame_handshake_done_t **const frame_storage);

#endif

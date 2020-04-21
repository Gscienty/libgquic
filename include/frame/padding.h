#ifndef _LIBGQUIC_FRAME_PADDING_H
#define _LIBGQUIC_FRAME_PADDING_H

typedef struct gquic_frame_padding_s gquic_frame_padding_t;
struct gquic_frame_padding_s { };

int gquic_frame_padding_alloc(gquic_frame_padding_t **const frame_storage);

#endif

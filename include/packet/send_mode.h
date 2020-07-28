/* include/packet/send_mode.h
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_PACKET_SEND_MODE_H
#define _LIBGQUIC_PACKET_SEND_MODE_H

#define GQUIC_SEND_MODE_NONE 0x00
#define GQUIC_SEND_MODE_ACK 0x01
#define GQUIC_SEND_MODE_PTO_INITIAL 0x02
#define GQUIC_SEND_MODE_PTO_HANDSHAKE 0x04
#define GQUIC_SEND_MODE_PTO_APP 0x08
#define GQUIC_SEND_MODE_ANY 0x10

#endif

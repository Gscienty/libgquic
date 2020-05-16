#!/bin/sh

gcc -DDEBUG -g -I include/ \
    src/*.c \
    src/flowcontrol/* \
    src/net/* \
    src/streams/* \
    src/event/* \
    src/tls/* \
    src/frame/* \
    src/handshake/* \
    src/packet/* \
    src/util/* \
    src/cong/* \
    src/coroutine/arch/$(uname -m)/*.s \
    src/coroutine/*.c \
    test/unit_test.c \
    $1 \
    -lpthread -lm -lcrypto \
    -o $2

./$2

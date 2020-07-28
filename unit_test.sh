#!/bin/sh

gcc -DDEBUG -DLOG -g -I include/ -I liteco/include/ -I liteco/include \
    liteco/src/arch/x86_64/*.s \
    liteco/src/*.c \
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
    test/unit_test.c \
    $1 \
    -lpthread -lm -lcrypto \
    -o $2

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:liteco/ valgrind ./$2

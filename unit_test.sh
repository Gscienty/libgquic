#!/bin/sh

cd liteco && make && cd ..

gcc -DDEBUG -g -I include/ -I liteco/include/ \
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
    -lpthread -lm -lcrypto -lliteco -Lliteco \
    -o $2

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:liteco/ ./$2

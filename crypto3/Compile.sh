#!/bin/sh
g++ -std=c++11 Keystore.cpp Main.cpp -o cipher -lcrypto
g++ -std=c++11 Builtin.cpp Player.cpp -o player -lcrypto


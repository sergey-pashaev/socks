#!/bin/bash

mkdir -p build/ && cd build/
#cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .. # gcc
CC=clang CXX=clang++ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .. # clang
make -j4
cd ../

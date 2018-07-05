#!/bin/bash

mkdir -p build/ && cd build/
#cmake -DTARGET_CPU=amd64 -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..  # gcc
CC=clang CXX=clang++ cmake -DTARGET_CPU=amd64 -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .. # clang
make -j4
cd ../

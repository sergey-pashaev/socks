#!/bin/bash

make clean
mkdir -p build/ && cd build/
export CCC_CC=clang
export CCC_CXX=clang++
scan-build cmake -DTARGET_CPU=amd64 -DUSE_CCACHE=OFF ..
scan-build make -j4
cd ../

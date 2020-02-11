#!/bin/bash
ROOT=`realpath $(dirname $0)`

echo "CC=clang-10"
echo "CXX=clang++"
echo "CFLAGS=-Xclang -load -Xclang $ROOT/llvm-plugins/libplugins-opt.so"
echo "CXXFLAGS=-Xclang -load -Xclang $ROOT/llvm-plugins/libplugins-opt.so"
echo "LDFLAGS=$ROOT/staticlib/obj/libmetadata.a -lpthread -lunwind $ROOT/metapagetable/obj/libmetapagetable.a $ROOT/gperftools-metalloc/.libs/libtcmalloc.a -ldl -lstdc++ -lm"
echo "LD_LIBRARY_PATH="


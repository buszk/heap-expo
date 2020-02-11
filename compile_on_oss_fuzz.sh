#!/bin/bash

ROOT=$(realpath .)
# Install dependencies for HeapExpo
apt update
apt install -y bison build-essential gettext git pkg-config python ssh subversion wget time
apt install -y libunwind-dev libtool-bin cmake
apt install -y vim
rm -f $(which llvm-config)-10
ln -s $(which llvm-config) $(which llvm-config)-10

# Build HeapExpo
CC=clang CXX=clang++ make -j

git clone https://github.com/buszk/compiler-wrapper /src/compiler-wrapper
CXX=clang++ CXXFLAGS="" make -C /src/compiler-wrapper
$ROOT/gen_wrapper_config.sh  > /src/compiler-wrapper/templates/heap-expo
export WRAP_CONFIG=/src/compiler-wrapper/templates/heap-expo
export CC=/src/compiler-wrapper/compiler-wrapper
export CXX=/src/compiler-wrapper/compiler-wrapper++
export CFLAGS="-O2 -g"
export CXXFLAGS="-O2 -g"
export LDFLAGS=

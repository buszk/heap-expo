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
make -j

# Export flags
CFLAGS_EXTRA="-Xclang -load -Xclang $ROOT/llvm-plugins/libplugins-opt.so"
CFLAGS=${CFLAGS//-O1}
CFLAGS=${CFLAGS//-fsanitize=address}
CFLAGS=${CFLAGS//-fsanitize-address-use-after-scope}
export CFLAGS="$CFLAGS $CFLAGS_EXTRA"
echo "CFLAGS = $CFLAGS"

CXXFLAGS=${CXXFLAGS//-fsanitize=address}
CXXFLAGS=${CXXFLAGS//-fsanitize-address-use-after-scope}
export CXXFLAGS="$CXXFLAGS $CFLAGS_EXTRA"

LDFLAGS_EXTRA="$ROOT/staticlib/obj/libmetadata.a $ROOT/metapagetable/obj/libmetapagetable.a $ROOT/gperftools-metalloc/.libs/libtcmalloc.a"
export LDFLAGS="$LDFLAGS_EXTRA"

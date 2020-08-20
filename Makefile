ROOT=$(readlink -f .)

all: gperftools-metalloc-build  metapagetable-build staticlib-build llvm-plugins-build

GD=gperftools-metalloc

$(GD)/Makefile:
	cd $(GD) && ./autogen.sh && CFLAGS="" CXXFLAGS="" ./configure

gperftools-metalloc-build: metapagetable-build $(GD)/Makefile
	make -C gperftools-metalloc -j

metapagetable-build:
	make -C metapagetable -j1

staticlib-build: metapagetable-build
	make -C staticlib

llvm-plugins-build:
	make -C llvm-plugins opt

test:
	make -C tests

clean:
	make -C llvm-plugins clean
	make -C gperftools-metalloc distclean
	make -C metapagetable clean
	make -C staticlib clean
	make -C tests clean

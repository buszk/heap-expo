ROOT=$(readlink -f .)

all: gperftools-metalloc-build  metapagetable-build staticlib-build llvm-plugins-build

gperftools-metalloc-build: metapagetable-build
	make -C gperftools-metalloc -j

metapagetable-build:
	make -C metapagetable -j1

staticlib-build: metapagetable-build
	make -C staticlib

llvm-plugins-build:
	make -C llvm-plugins

test:
	make -C tests

clean:
	make -C llvm-plugins clean
	make -C gperftools-metalloc clean
	make -C metapagetable clean
	make -C staticlib clean

CC=g++
CONFIG=/home/zekun/repo/dangsan-build/dangsan/autosetup.dir/install/common/bin/llvm-config
INCLUDES=-I. -I../staticlib -I../metapagetable
CFLAGS=-Wall -std=c++0x -g `$(CONFIG) --cxxflags` -O2
LDFLAGS=-g -shared `$(CONFIG) --ldflags`


LLVMHeapExpo.so: StackPointerTracker.cpp $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<


clean:
	rm -rf LLVMHeapExpo.so
	

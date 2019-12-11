CC=g++
CONFIG=llvm-config
INCLUDES=-I. -I../staticlib -I../metapagetable
CFLAGS=-Wall -std=c++0x -g `$(CONFIG) --cxxflags` -O2
LDFLAGS=-g -shared `$(CONFIG) --ldflags`

LLVMHeapExpo.so: StackPointerTracker.cpp $(OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	[ ! -z "$(TARGETDIR)" ] && mv LLVMHeapExpo.so $(TARGETDIR) || echo TARGETDIR not set

clean:
	rm -rf LLVMHeapExpo.so
	

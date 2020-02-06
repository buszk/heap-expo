LLVM_VERSION=10
CC=clang-$(LLVM_VERSION)
CONF=llvm-config-$(LLVM_VERSION)
INCLUDES=-I. -I../staticlib -I../metapagetable
CFLAGS=-c -Wall -g `$(CONF) --cxxflags` -O0 -fPIC
LDFLAGS=-g -shared `$(CONF) --ldflags` -lLLVM -lstdc++ -Wl,-znodelete
TARGETDIR=.
OBJDIR=$(TARGETDIR)/obj
#GOLDINSTDIR=$(METALLOC_HOME)/autosetup.dir/install/common
GOLDINSTDIR=/usr/lib/llvm-$(LLVM_VERSION)
LINKWITHGOLDFLAGS=-Wl,--no-undefined -L $(GOLDINSTDIR)/lib/ -l:LLVMgold.so -Wl,--rpath=$(GOLDINSTDIR)/lib

EXE=$(TARGETDIR)/libplugins.so
EXE2=$(TARGETDIR)/libplugins-opt.so

SRCS    := $(wildcard *.cpp)
OBJS    := $(patsubst %.cpp,$(OBJDIR)/%.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)

all: $(EXE) $(EXE2)

clean:
	rm $(OBJDIR)/*.o
	rm $(OBJDIR)/*.d
	rm $(EXE)
	rm $(EXE2)

$(EXE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) $(LINKWITHGOLDFLAGS) -o $@

$(EXE2): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

-include $(DEPS)

$(OBJDIR)/%.o: %.cpp
	mkdir -p $(OBJDIR)
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $<
	

LLVM_VERSION=10
CC=clang-$(LLVM_VERSION)
CONF=llvm-config-$(LLVM_VERSION)
INCLUDES=-I. -I../staticlib -I../metapagetable
CFLAGS=-c -Wall -g `$(CONF) --cxxflags` -O0 -fPIC
LDFLAGS=-g -shared `$(CONF) --ldflags` -lstdc++ -Wl,-znodelete
TARGETDIR=.
OBJDIR=$(TARGETDIR)/obj
#GOLDINSTDIR=$(METALLOC_HOME)/autosetup.dir/install/common
GOLDINSTDIR=/usr/lib/llvm-$(LLVM_VERSION)
LINKWITHGOLDFLAGS=-Wl,--no-undefined -L $(GOLDINSTDIR)/lib/ -l:LLVMgold.so -Wl,--rpath=$(GOLDINSTDIR)/lib -lLLVM

EXE=$(TARGETDIR)/libplugins.so
EXE2=$(TARGETDIR)/libplugins-opt.so
EXEDS=$(TARGETDIR)/libplugins-dangsan.so

SRCS    := $(wildcard *.cpp)
SRCSDS  := $(filter-out StackPointerTracker.cpp,$(SRCS))
OBJS    := $(patsubst %.cpp,$(OBJDIR)/%.o,$(SRCS))
OBJSDS  := $(patsubst %.cpp,$(OBJDIR)/%.o,$(SRCSDS))
DEPS    := $(OBJS:.o=.d)

all: $(EXE) $(EXE2) $(EXEDS)

opt: $(EXE2) $(EXEDS)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(OBJDIR)/*.d
	rm -f $(EXE)
	rm -f $(EXE2)

$(EXE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) $(LINKWITHGOLDFLAGS) -o $@

$(EXE2): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(EXEDS): $(OBJSDS)
	$(CC) $(OBJSDS) $(LDFLAGS) -o $@

-include $(DEPS)

$(OBJDIR)/%.o: %.cpp
	mkdir -p $(OBJDIR)
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $<
	

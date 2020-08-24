CC=g++
INCLUDES=-I. -I../staticlib -I../metapagetable
CFLAGS=-c -Werror -Wall -std=c++0x -g `llvm-config --cxxflags` -O0
LDFLAGS=-g -shared
TARGETDIR=.
OBJDIR=$(TARGETDIR)/obj
GOLDINSTDIR=$(METALLOC_HOME)/autosetup.dir/install/common
LINKWITHGOLDFLAGS=-Wl,--no-undefined -L $(GOLDINSTDIR)/lib/ -l:LLVMgold.so -Wl,--rpath=$(GOLDINSTDIR)/lib

EXE=$(TARGETDIR)/libplugins.so
EXE2=$(TARGETDIR)/libplugins-opt.so
EXE3=$(TARGETDIR)/libplugins-heapexpo.so
EXE4=$(TARGETDIR)/libplugins-heapexpo-opt.so

SRCS    := $(wildcard *.cpp)
HE_SRCS := Mem2Reg.cpp StackVolatileOptimizer.cpp
SRCS_DS := $(filter-out $(HE_SRCS), $(SRCS))
OBJS    := $(patsubst %.cpp,$(OBJDIR)/%.o,$(SRCS))
OBJS_DS := $(patsubst %.cpp,$(OBJDIR)/%.o,$(SRCS_DS))
DEPS    := $(OBJS:.o=.d)

all: $(EXE) $(EXE2) $(EXE3) $(EXE4)

clean:
	rm $(OBJDIR)/*.o
	rm $(OBJDIR)/*.d
	rm $(EXE)
	rm $(EXE2)
	rm $(EXE3)
	rm $(EXE4)

$(EXE): $(OBJS_DS) $(TARGETDIR)
	$(CC) $(OBJS_DS) $(LDFLAGS) $(LINKWITHGOLDFLAGS) -o $@

$(EXE2): $(OBJS_DS) $(TARGETDIR)
	$(CC) $(OBJS_DS) $(LDFLAGS) -o $@


$(EXE3): $(OBJS) $(TARGETDIR)
	$(CC) $(OBJS) $(LDFLAGS) $(LINKWITHGOLDFLAGS) -o $@

$(EXE4): $(OBJS) $(TARGETDIR)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

-include $(DEPS)

$(OBJDIR)/%.o: %.cpp $(OBJDIR)
	$(CC) $(INCLUDES) $(CFLAGS) -MMD -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGETDIR):
	mkdir -p $(TARGETDIR)


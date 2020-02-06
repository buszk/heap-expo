PAGESIZE:= $(shell getconf PAGESIZE)
LTCC=libtool --tag=CC --mode=compile gcc -prefer-pic
LINKER=libtool --tag=CC --mode=link gcc
CC=gcc
# LINKER=gcc
INCLUDES=-I. -I../gperftools-metalloc/src/ -I$(OBJDIR)
# INCLUDES=-I. -I$(OBJDIR)
CFLAGS=-fPIC -c -Werror -Wall -O3 -std=gnu11 -DSYSTEM_PAGESIZE=$(PAGESIZE) -g
LDFLAGS=-static
OBJDIR=obj

EXE=$(OBJDIR)/libmetapagetable.a
EXE2=$(OBJDIR)/libmetapagetable.la

SRCS    := $(wildcard *.c)
OBJS    := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
OBJS2   := $(patsubst %.c,$(OBJDIR)/%.lo,$(SRCS))
DEPS    := $(OBJS:.o=.d)
all: $(OBJDIR)/metapagetable.h $(OBJDIR)/metapagetable_core.h $(EXE) $(EXE2)

clean:
	rm -rf $(OBJDIR)
	rm -f linker-options
	rm -f metapagetable.h

$(EXE): $(OBJS)
	ls $(OBJS)
	mkdir -p $(OBJDIR)
	ar crv $@ $(OBJS)
	ranlib $@

$(EXE2): $(OBJS2)
	mkdir -p $(OBJDIR)
	$(LINKER) $(OBJS2) $(LDFLAGS) -o $@

-include $(DEPS)

$(OBJDIR)/%.o: %.c  $(OBJDIR)/metapagetable.h
	mkdir -p $(OBJDIR)
	$(CC) $(INCLUDES) $(CFLAGS) -o $@ $<

$(OBJDIR)/%.lo: %.c  $(OBJDIR)/metapagetable.h
	mkdir -p $(OBJDIR)
	$(LTCC) $(INCLUDES) $(CFLAGS) -MT $@ -MMD -o $@ $<

$(OBJDIR)/metapagetable.h: metapagetable.h.in linker-options.in config_metapagetable.cmake
	mkdir -p $(OBJDIR)
	rm -f metapagetable.h
	rm -f linker-options
	rm -f $(OBJDIR)/metapagetable.h
	rm -f $(OBJDIR)/linker-options
	cmake $(METALLOC_OPTIONS) -P ./config_metapagetable.cmake
	mv linker-options $(OBJDIR)
	cp metapagetable.h $(OBJDIR)

$(OBJDIR)/metapagetable_core.h: metapagetable_core.h
	mkdir -p $(OBJDIR)
	cp metapagetable_core.h $(OBJDIR)

touch_config:
	touch metapagetable.h.in
	touch linker-options.in

config: touch_config
	$(MAKE) $(OBJDIR)/metapagetable.h

directories:
	mkdir -p $(OBJDIR)



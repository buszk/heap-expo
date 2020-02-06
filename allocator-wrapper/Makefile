CC=gcc
CFLAGS=-c -Werror -Wall -fPIC -std=gnu11
all: libwrapalloc.a

libwrapalloc.a:	allocator-wrapper.o
	ar crv $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf libwrapalloc.a *.o
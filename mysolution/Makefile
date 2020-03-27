CC=gcc

CFLAGS=-Wall -Werror -fPIC -DPIC -std=gnu99 -I../include

LDFLAGS=-L../lib

LDLIBS=-ldirtree

all: server mylib.so

mylib.so: mylib.o 
	$(LD) -shared -o mylib.so mylib.o $(LDFLAGS) -ldl $(LDLIBS)

server: server.c
	$(CC) -o server server.c -I../include $(LDFLAGS) $(LDLIBS)

.PHONY: all clean

clean:
	rm -rf *.o *.so server


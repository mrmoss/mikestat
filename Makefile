C=gcc
CFLAGS=-O -Wall -static -static-libstdc++ -static-libgcc

all: mikestat32 mikestat64

mikestat32: mikestat.c
	$(C) $(CFLAGS) -m32 $^ -o $@

mikestat64: mikestat.c
	$(C) $(CFLAGS) -m64 $^ -o $@
clean:
	- rm -f mikestat32 mikestat64

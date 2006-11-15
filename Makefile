# makedumpfile

VERSION=1.0.4
DATE=15 November 2006

CC	= gcc
CFLAGS = -g -O2 -Wall -D_FILE_OFFSET_BITS=64 \
	  -DVERSION='"$(VERSION)"' -DRELEASE_DATE='"$(DATE)"'
CFLAGS_ARCH	= -g -O2 -Wall

ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/sun4u/sparc64/ \
			       -e s/arm.*/arm/ -e s/sa110/arm/ \
			       -e s/s390x/s390/ -e s/parisc64/parisc/ \
			       -e s/ppc64/powerpc/ )
CFLAGS += -D__$(ARCH)__
CFLAGS_ARCH += -D__$(ARCH)__
SRC	= makedumpfile.c makedumpfile.h diskdump_mod.h
SRC_ARCH = x86.c x86_64.c ia64.c
OBJ_ARCH = x86.o x86_64.o ia64.o

all: makedumpfile

$(OBJ_ARCH): $(SRC_ARCH)
	$(CC) $(CFLAGS_ARCH) -c -o ./$@ ./$(@:.o=.c) 

makedumpfile: $(SRC) $(OBJ_ARCH)
	$(CC) $(CFLAGS) $(OBJ_ARCH) -o $@ $< -static -ldw -lelf -lz

clean:
	rm $(OBJ) $(OBJ_ARCH) makedumpfile

install:
	cp ./makedumpfile /bin

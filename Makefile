# makedumpfile

VERSION=1.4.0
DATE=12 September 2011

CC	= gcc
CFLAGS = -g -O2 -Wall -D_FILE_OFFSET_BITS=64 \
	  -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE \
	  -DVERSION='"$(VERSION)"' -DRELEASE_DATE='"$(DATE)"'
CFLAGS_ARCH	= -g -O2 -Wall -D_FILE_OFFSET_BITS=64 \
		    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# LDFLAGS = -L/usr/local/lib -I/usr/local/include

ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/sun4u/sparc64/ \
			       -e s/arm.*/arm/ -e s/sa110/arm/ \
			       -e s/s390x/s390/ -e s/parisc64/parisc/ \
			       -e s/ppc64/powerpc/ )
CFLAGS += -D__$(ARCH)__
CFLAGS_ARCH += -D__$(ARCH)__

ifeq ($(ARCH), powerpc)
CFLAGS += -m64
CFLAGS_ARCH += -m64
endif

SRC	= makedumpfile.c makedumpfile.h diskdump_mod.h
SRC_PART = print_info.c dwarf_info.c elf_info.c erase_info.c
OBJ_PART = print_info.o dwarf_info.o elf_info.o erase_info.o
SRC_ARCH = arch/arm.c arch/x86.c arch/x86_64.c arch/ia64.c arch/ppc64.c arch/s390x.c
OBJ_ARCH = arch/arm.o arch/x86.o arch/x86_64.o arch/ia64.o arch/ppc64.o arch/s390x.o

all: makedumpfile

$(OBJ_PART): $(SRC_PART)
	$(CC) $(CFLAGS) -c -o ./$@ ./$(@:.o=.c) 

$(OBJ_ARCH): $(SRC_ARCH)
	$(CC) $(CFLAGS_ARCH) -c -o ./$@ ./$(@:.o=.c) 

makedumpfile: $(SRC) $(OBJ_PART) $(OBJ_ARCH)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ_PART) $(OBJ_ARCH) -o $@ $< -static -ldw -lbz2 -lebl -ldl -lelf -lz
	echo .TH MAKEDUMPFILE 8 \"$(DATE)\" \"makedumpfile v$(VERSION)\" \"Linux System Administrator\'s Manual\" > temp.8
	grep -v "^.TH MAKEDUMPFILE 8" makedumpfile.8 >> temp.8
	mv temp.8 makedumpfile.8
	gzip -c ./makedumpfile.8 > ./makedumpfile.8.gz
	echo .TH MAKEDUMPFILE.CONF 5 \"$(DATE)\" \"makedumpfile v$(VERSION)\" \"Linux System Administrator\'s Manual\" > temp.5
	grep -v "^.TH MAKEDUMPFILE.CONF 5" makedumpfile.conf.5 >> temp.5
	mv temp.5 makedumpfile.conf.5
	gzip -c ./makedumpfile.conf.5 > ./makedumpfile.conf.5.gz

clean:
	rm -f $(OBJ) $(OBJ_PART) $(OBJ_ARCH) makedumpfile makedumpfile.8.gz makedumpfile.conf.5.gz

install:
	cp makedumpfile ${DESTDIR}/bin
	cp makedumpfile-R.pl ${DESTDIR}/bin
	cp makedumpfile.8.gz ${DESTDIR}/usr/share/man/man8
	cp makedumpfile.conf.5.gz ${DESTDIR}/usr/share/man/man5
	cp makedumpfile.conf ${DESTDIR}/etc/makedumpfile.conf.sample

